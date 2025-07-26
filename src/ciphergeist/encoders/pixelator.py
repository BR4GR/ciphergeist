import asyncio
import hashlib
import json
import lzma
import mimetypes
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional, Union

import httpx
import magic
import numpy as np
from PIL import Image


@dataclass
class ChunkInfo:
    """Information about a data chunk."""

    chunk_id: int
    image_name: str
    data_bytes: int
    chunk_hash: str


@dataclass
class EncodingResult:
    """Result of document encoding process."""

    metadata_image: str
    chunk_images: list[str]
    total_size: int
    chunk_count: int


class Pixelator:
    """
    Document-to-Image encoder with optional encryption and metadata management.

    Converts documents to image files with comprehensive metadata
    tracking and recovery capabilities. Supports optional XOR encryption.
    """

    IMAGE_WIDTH = 160
    IMAGE_HEIGHT = 125
    IMAGE_CHANNELS = 3
    ERROR_CORRECTION_RATIO = 0.2
    CHUNK_OVERLAP_BYTES = 2**7  # 128 bytes overlap for error recovery

    def __init__(self, encryption_key: Optional[str] = None) -> None:
        """
        Initialize Pixelator.

        Args:
            encryption_key: Optional XOR encryption key. If None, no encryption is used.
        """
        self.encryption_key = encryption_key
        self._magic = magic.Magic(mime=True)
        self._http_client = httpx.AsyncClient(timeout=10.0)
        self.image_capacity = self.IMAGE_WIDTH * self.IMAGE_HEIGHT * self.IMAGE_CHANNELS
        self.chunk_size = self._calculate_optimal_chunk_size()

    def _calculate_optimal_chunk_size(self) -> int:
        """
        Calculate the maximum data chunk size that can fit in an image
        after accounting for recovery overhead.
        """
        # Formula: Capacity = Chunk + (Chunk * ErrorRatio) + Overlap
        # Rearranged: Capacity - Overlap = Chunk * (1 + ErrorRatio)
        # Therefore: Chunk = (Capacity - Overlap) / (1 + ErrorRatio)

        usable_capacity = self.image_capacity - self.CHUNK_OVERLAP_BYTES
        optimal_size = usable_capacity / (1 + self.ERROR_CORRECTION_RATIO)

        # Return as an integer, ensuring it's a multiple of 8 for clean boundaries
        return int(optimal_size // 8 * 8)

    def _xor_encrypt_decrypt(self, data: bytes, key: str) -> bytes:
        """XOR encrypt/decrypt data with a repeating key."""
        if not key:
            return data

        key_bytes = key.encode("utf-8")
        result = bytearray()
        key_len = len(key_bytes)

        for i, byte in enumerate(data):
            result.append(byte ^ key_bytes[i % key_len])

        return bytes(result)

    def _check_chunk_exists(self, chunk_path: Path, image_name: str) -> None:
        """Check if chunk file exists and raise error if not."""
        if not chunk_path.exists():
            raise FileNotFoundError(f"Chunk image not found: {image_name}")

    def _verify_chunk_integrity(self, chunk_data: bytes, expected_hash: str, image_name: str) -> None:
        """Verify chunk integrity and raise error if invalid."""
        chunk_hash = self._calculate_hash(chunk_data)
        if chunk_hash != expected_hash:
            raise ValueError(f"Chunk integrity check failed: {image_name}")

    async def encode_document(
        self, file_path: Union[str, Path], output_dir: Union[str, Path] = "output"
    ) -> EncodingResult:
        """
        Encode document to images with optional encryption.

        Args:
            file_path: Path to document to encode
            output_dir: Directory to save encoded images

        Returns:
            EncodingResult with metadata and image information

        Raises:
            FileNotFoundError: If input file doesn't exist
            ValueError: If file cannot be processed
        """
        file_path = Path(file_path)
        output_dir = Path(output_dir)
        output_dir.mkdir(exist_ok=True)

        # Step 1: Process document
        document_data, file_metadata = self._process_document(file_path)

        # Step 2: Optionally encrypt data
        if self.encryption_key:
            encrypted_data = self._xor_encrypt_decrypt(document_data, self.encryption_key)
        else:
            encrypted_data = document_data

        # Step 3: Create chunks
        chunks = self._create_chunks(encrypted_data)

        # Step 4: Generate image names
        chunk_names = await self._generate_image_names(len(chunks))

        # Create metadata image name based on document name
        document_name = file_path.stem  # Get filename without extension
        metadata_image_name = f"{document_name}_metadata.png"

        # Step 5: Create chunk images
        chunk_infos = []
        chunk_images = []

        for i, (chunk_data, filename) in enumerate(zip(chunks, chunk_names)):
            chunk_hash = self._calculate_hash(chunk_data)
            image_path = output_dir / filename

            self._encode_data_to_image(chunk_data, image_path)

            chunk_infos.append(
                ChunkInfo(chunk_id=i, image_name=filename, data_bytes=len(chunk_data), chunk_hash=chunk_hash)
            )
            chunk_images.append(filename)

        # Step 6: Create metadata
        metadata = self._create_metadata(file_metadata, chunk_infos, encrypted_data)

        # Step 7: Create metadata image
        metadata_path = output_dir / metadata_image_name
        metadata_json = json.dumps(metadata, indent=2).encode("utf-8")

        self._encode_data_to_image(metadata_json, metadata_path)

        return EncodingResult(
            metadata_image=metadata_image_name,
            chunk_images=chunk_images,
            total_size=len(encrypted_data),
            chunk_count=len(chunks),
        )

    async def decode_document(
        self,
        metadata_image_path: Union[str, Path],
        output_path: Union[str, Path],
        images_dir: Optional[Union[str, Path]] = None,
    ) -> bool:
        """
        Decode document from images with optional decryption.

        Args:
            metadata_image_path: Path to metadata image
            output_path: Path where to save decoded document
            images_dir: Directory containing chunk images (default: same as metadata)

        Returns:
            True if successful, False otherwise
        """
        metadata_image_path = Path(metadata_image_path)
        output_path = Path(output_path)

        images_dir = metadata_image_path.parent if images_dir is None else Path(images_dir)

        try:
            # Step 1: Decode metadata
            metadata_data = self._decode_data_from_image(metadata_image_path)
            metadata = json.loads(metadata_data.decode("utf-8"))

            # Step 2: Collect chunks
            chunks_data = []
            chunk_infos = metadata["chunks"]["images"]

            for image_name, chunk_info in chunk_infos.items():
                chunk_path = images_dir / image_name
                self._check_chunk_exists(chunk_path, image_name)

                chunk_data = self._decode_data_from_image(chunk_path)
                expected_size = chunk_info["data_bytes"]
                chunk_data = chunk_data[:expected_size]  # Trim to exact size

                # Verify chunk integrity
                self._verify_chunk_integrity(chunk_data, chunk_info["chunk_hash"], image_name)

                chunks_data.append((chunk_info["chunk_id"], chunk_data))

            # Step 3: Reassemble data
            chunks_data.sort(key=lambda x: x[0])  # Sort by chunk_id
            assembled_data = b"".join(chunk[1] for chunk in chunks_data)

            # Step 4: Optionally decrypt data
            if self.encryption_key and metadata.get("encryption", {}).get("algorithm") == "xor":
                document_data = self._xor_encrypt_decrypt(assembled_data, self.encryption_key)
            else:
                document_data = assembled_data

            # Step 5: Decompress and save
            original_data = lzma.decompress(document_data)
            output_path.write_bytes(original_data)

        except Exception as e:
            print(f"Decoding failed: {e}")
            return False
        else:
            return True

    def _process_document(self, file_path: Path) -> tuple[bytes, dict[str, Any]]:
        """Process document and generate metadata."""
        if not file_path.exists():
            raise FileNotFoundError(f"Document not found: {file_path}")

        original_data = file_path.read_bytes()
        file_extension, mime_type = self._detect_file_type(file_path)
        compressed_data = lzma.compress(original_data, preset=6)

        metadata = {
            "filename": file_path.name,
            "extension": file_extension,
            "mime_type": mime_type,
            "original_size": len(original_data),
            "compressed_size": len(compressed_data),
            "hash": self._calculate_hash(original_data),
        }

        return compressed_data, metadata

    def _detect_file_type(self, file_path: Path) -> tuple[str, str]:
        """Detect file type and MIME type."""
        try:
            mime_type = self._magic.from_file(str(file_path))
        except Exception:
            guessed_mime_type, _ = mimetypes.guess_type(str(file_path))
            mime_type = guessed_mime_type or "application/octet-stream"

        # Get extension
        if file_path.suffix:
            extension = file_path.suffix.lower()
        else:
            guessed_extension = mimetypes.guess_extension(mime_type)
            extension = guessed_extension if guessed_extension else ".bin"

        return extension, mime_type

    def _create_chunks(self, data: bytes) -> list[bytes]:
        """Split data into chunks."""
        chunks = []
        for i in range(0, len(data), self.chunk_size):
            chunk = data[i : i + self.chunk_size]
            chunks.append(chunk)
        return chunks

    async def _generate_image_names(self, count: int) -> list[str]:
        """Generate random filenames for images."""
        names = []
        for _ in range(count):
            try:
                # Try to get random name from API
                response = await self._http_client.get("https://randomuser.me/api/?inc=email")
                response.raise_for_status()

                data = response.json()
                name_data = data["results"][0]["email"].split("@")[0]
                filename = f"{name_data}.png"
                # strip al non-alphanumeric characters

                names.append(filename)

            except Exception:
                filename = f"{uuid.uuid4().hex}.png"
                names.append(filename)

        return names

    def _encode_data_to_image(self, data: bytes, output_path: Path) -> None:
        """Encode binary data into PNG image."""
        # Calculate required pixels
        data_length = len(data)
        total_pixels = self.IMAGE_WIDTH * self.IMAGE_HEIGHT
        max_capacity = total_pixels * self.IMAGE_CHANNELS

        if data_length > max_capacity:
            raise ValueError(f"Data too large: {data_length} > {max_capacity}")

        # Pad data to fill image if needed
        padded_data = data + b"\x00" * (max_capacity - data_length)

        # Convert to numpy array and reshape
        data_array = np.frombuffer(padded_data, dtype=np.uint8)
        image_array = data_array.reshape((self.IMAGE_HEIGHT, self.IMAGE_WIDTH, self.IMAGE_CHANNELS))

        # Create and save image
        image = Image.fromarray(image_array, "RGB")
        image.save(output_path, "PNG")

    def _decode_data_from_image(self, image_path: Path) -> bytes:
        """Decode binary data from PNG image."""
        # Load image
        image = Image.open(image_path)
        image_array = np.array(image)

        # Flatten to bytes
        data_bytes = image_array.flatten().tobytes()

        return data_bytes

    def _create_metadata(
        self, file_metadata: dict[str, Any], chunk_infos: list[ChunkInfo], processed_data: bytes
    ) -> dict[str, Any]:
        """Create comprehensive metadata structure."""
        chunks_dict = {}
        for chunk_info in chunk_infos:
            chunks_dict[chunk_info.image_name] = {
                "chunk_id": chunk_info.chunk_id,
                "data_bytes": chunk_info.data_bytes,
                "chunk_hash": chunk_info.chunk_hash,
            }

        metadata = {
            "version": "1.0.0",
            "document": {
                "filename": file_metadata["filename"],
                "extension": file_metadata["extension"],
                "mime_type": file_metadata["mime_type"],
                "original_size": file_metadata["original_size"],
                "compressed_size": file_metadata["compressed_size"],
                "hash": file_metadata["hash"],
            },
            "chunks": {
                "total": len(chunk_infos),
                "chunk_size": self.chunk_size,
                "total_processed_size": len(processed_data),
                "images": chunks_dict,
            },
            "recovery": {
                "error_correction_ratio": self.ERROR_CORRECTION_RATIO,
                "chunk_overlap_bytes": self.CHUNK_OVERLAP_BYTES,
            },
        }

        # Add encryption info if key is used
        if self.encryption_key:
            metadata["encryption"] = {
                "algorithm": "xor",
                "encrypted": True,
            }
        else:
            metadata["encryption"] = {
                "algorithm": "none",
                "encrypted": False,
            }

        return metadata

    def _calculate_hash(self, data: bytes) -> str:
        """Calculate SHA-256 hash."""
        return hashlib.sha256(data).hexdigest()

    async def close(self) -> None:
        """Clean up resources."""
        await self._http_client.aclose()

    async def __aenter__(self) -> "Pixelator":
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit."""
        await self.close()


async def main() -> None:
    """Example usage of Pixelator."""
    import shutil

    output_dir = Path("output/pixelatortest")

    # Clear the output directory first for easier testing
    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    async with Pixelator() as pixelator:
        result = await pixelator.encode_document("src/ciphergeist/books/dracula.txt", output_dir)
        print(f"Encoded to {result.chunk_count} images")
        print(f"Metadata image: {result.metadata_image}")
        print(f"Output directory: {output_dir}")
        print(f"Total size: {result.total_size} bytes")

        # Decode document
        # success = await pixelator.decode_document(f"{output_dir}/{result.metadata_image}", "decoded_dracula.txt", output_dir)
        # print(f"Decoding {'successful' if success else 'failed'}")


if __name__ == "__main__":
    asyncio.run(main())
