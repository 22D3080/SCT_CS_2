from PIL import Image
import numpy as np
import hashlib
import os

def process_image(input_path, output_path, key, mode='encrypt'):
    """
    Encrypts or decrypts an image by shuffling pixels and applying an XOR operation.
    :param input_path: Path to the input image.
    :param output_path: Path to save the processed image.
    :param key: Key for encryption/decryption (string or bytes).
    :param mode: 'encrypt' or 'decrypt'.
    """
    try:
        # Open the image and convert to RGB
        img = Image.open(input_path).convert('RGB')
        pixels = np.array(img)
        height, width, channels = pixels.shape

        # Flatten the pixel array (so we have one long list of pixels)
        flat_pixels = pixels.reshape(-1, channels)
        num_pixels = flat_pixels.shape[0]

        # Ensure key is in bytes
        if isinstance(key, str):
            key = key.encode('utf-8')

        # Derive a key stream using SHA-256
        key_stream = bytearray()
        counter = 0
        while len(key_stream) < num_pixels * channels:
            counter_bytes = counter.to_bytes(4, 'big')
            hash_input = key + counter_bytes
            key_stream.extend(hashlib.sha256(hash_input).digest())
            counter += 1
        key_stream = np.frombuffer(key_stream[:num_pixels * channels], dtype=np.uint8).reshape(num_pixels, channels)

        # Generate a permutation of indices based on the key stream
        seed = int.from_bytes(key_stream[:4].tobytes(), 'big') % 2**32
        np.random.seed(seed)
        indices = np.arange(num_pixels)
        np.random.shuffle(indices)

        if mode == 'encrypt':
            # Shuffle pixels and apply XOR with key stream
            processed_pixels = np.bitwise_xor(flat_pixels[indices], key_stream)

            # Save permutation indices for decryption
            np.save(output_path + '_permutation.npy', indices)  # This saves the permutation for later use

        elif mode == 'decrypt':
            # Load permutation indices
            permutation_file = input_path + '_permutation.npy'
            if not os.path.exists(permutation_file):
                raise FileNotFoundError(f"Permutation file {permutation_file} not found.")
            indices = np.load(permutation_file)  # Load the saved permutation

            # Apply XOR with key stream and reverse shuffle
            unshuffled_pixels = np.bitwise_xor(flat_pixels, key_stream)
            reverse_indices = np.argsort(indices)  # Reverse the shuffle using the permutation
            processed_pixels = unshuffled_pixels[reverse_indices]

        else:
            raise ValueError("Mode should be 'encrypt' or 'decrypt'.")

        # Reshape and save the processed image
        processed_pixels = processed_pixels.reshape(height, width, channels)
        Image.fromarray(processed_pixels.astype('uint8')).save(output_path)
        print(f"Image successfully {mode}ed and saved to {output_path}.")
    except Exception as e:
        print(f"An error occurred: {e}")


# Example usage:
# Encrypting an image
process_image(
    r"C:\Users\Lenovo\OneDrive\Desktop\SkillCraft Projects\Task_image.jpg", r"C:\Users\Lenovo\OneDrive\Desktop\SkillCraft Projects\encrypted_focus.jpeg", key='my_secure_key', mode='encrypt'
)

# Decrypting the image
process_image(
    r"C:\Users\Lenovo\OneDrive\Desktop\SkillCraft Projects\encrypted_focus.jpeg", r"C:\Users\Lenovo\OneDrive\Desktop\SkillCraft Projects\decrypted_focus.jpeg", key='my_secure_key', mode='decrypt'
)
