import os
import subprocess
import sys

def setup_model():
    print("Installing specific versions of required packages...")
    # Install specific versions to avoid compatibility issues
    subprocess.check_call([sys.executable, "-m", "pip", "install",
                           "huggingface_hub==0.17.3",
                           "transformers==4.35.0"])

    from huggingface_hub import login, hf_hub_download

    print("Logging in to Hugging Face...")
    # Use the provided token for authentication
    token = "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"
    login(token=token)

    # Define the model we want to download
    model_id = "Qwen/Qwen2.5-Coder-7B-Instruct-GGUF"
    model_file = "qwen2.5-coder-7b-instruct-q4_k_m.gguf"  # Using 4-bit quantization for smaller size

    print(f"Downloading {model_file} from {model_id}...")
    try:
        # Check if model is already downloaded
        if os.path.exists(f"model/{model_file}"):
            print(f"Model already exists at model/{model_file}")
            return True

        # Download the model
        model_path = hf_hub_download(
            repo_id=model_id,
            filename=model_file,
            local_dir="model",
            local_dir_use_symlinks=False
        )

        print(f"Model downloaded successfully to {model_path}")
        return True
    except Exception as e:
        print(f"Error downloading model: {e}")
        return False

if __name__ == "__main__":
    setup_model()