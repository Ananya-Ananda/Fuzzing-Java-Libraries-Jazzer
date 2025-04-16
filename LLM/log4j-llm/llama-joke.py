import torch
from transformers import AutoTokenizer, AutoModelForCausalLM
import os

def generate_joke_with_llama():
    print("Loading Llama model and tokenizer...")
    
    # Use the model you've been granted access to
    model_name = "meta-llama/Llama-3.3-70B-Instruct"
    
    # Set cache directories to use scratch space
    cache_dir = "/scratch/ckp6ac/log4j_llm_fuzzing"
    os.environ["TRANSFORMERS_CACHE"] = cache_dir
    os.environ["HF_HOME"] = cache_dir
    
    # You need to set up your Hugging Face token
    huggingface_token = input("Enter your Hugging Face token: ")
    
    print(f"Using cache directory: {cache_dir}")
    print("Downloading and loading model, this may take a while...")
    
    # Load tokenizer with authentication and specific cache directory
    tokenizer = AutoTokenizer.from_pretrained(
        model_name,
        token=huggingface_token,
        cache_dir=cache_dir
    )
    
    # Load model with authentication and optimizations for large models
    model = AutoModelForCausalLM.from_pretrained(
        model_name,
        token=huggingface_token,
        cache_dir=cache_dir,
        torch_dtype=torch.float16,  # Use half precision
        device_map="auto",          # Automatically distribute across available GPUs
        load_in_8bit=True           # Use 8-bit quantization to reduce VRAM usage
    )
    
    print("Model loaded. Generating a joke...")
    
    # Prompt for joke generation
    prompt = """
    You are a helpful AI assistant. Please tell me a funny programming joke.
    """
    
    # Encode the prompt
    inputs = tokenizer(prompt, return_tensors="pt").to(model.device)
    
    # Generate a response
    with torch.no_grad():
        output = model.generate(
            inputs["input_ids"],
            max_length=300,
            num_return_sequences=1,
            temperature=0.7,
            top_p=0.9,
            do_sample=True
        )
    
    # Decode the response
    joke = tokenizer.decode(output[0], skip_special_tokens=True)
    
    return joke

if __name__ == "__main__":
    print("Starting joke generator...")
    
    # Create the cache directory if it doesn't exist
    os.makedirs("/scratch/ckp6ac/log4j_llm_fuzzing", exist_ok=True)
    
    joke = generate_joke_with_llama()
    print("\n=== Here's your joke ===")
    print(joke)
    print("========================")