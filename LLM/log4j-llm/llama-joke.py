import torch
from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig
import os

def generate_joke_with_llama():
    print("Loading Llama model and tokenizer...")
    
    # Since you have an A100 with 80GB VRAM, you can use the 70B model if desired
    model_name = "meta-llama/Llama-3.3-70B-Instruct"  # Or use meta-llama/Llama-3-8B-Instruct for faster loading
    
    # Set cache directories to use scratch space
    cache_dir = "/scratch/ckp6ac/log4j_llm_fuzzing"
    os.environ["TRANSFORMERS_CACHE"] = cache_dir
    os.environ["HF_HOME"] = cache_dir
    
    # You need to set up your Hugging Face token
    huggingface_token = input("Enter your Hugging Face token: ")
    
    print(f"Using cache directory: {cache_dir}")
    print(f"Using model: {model_name}")
    print("Downloading and loading model, this may take a while...")
    
    # Load tokenizer with authentication and specific cache directory
    tokenizer = AutoTokenizer.from_pretrained(
        model_name,
        token=huggingface_token,
        cache_dir=cache_dir
    )
    
    # Create BitsAndBytesConfig for efficient inference
    # With 80GB VRAM, you can use 4-bit quantization for best performance/quality balance
    quantization_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_compute_dtype=torch.float16,
        bnb_4bit_use_double_quant=True,
        bnb_4bit_quant_type="nf4"
    )
    
    # Load model with efficient settings for A100
    model = AutoModelForCausalLM.from_pretrained(
        model_name,
        token=huggingface_token,
        cache_dir=cache_dir,
        quantization_config=quantization_config,
        device_map="auto",
        torch_dtype=torch.float16
    )
    
    print("Model loaded successfully!")
    print("Generating a joke...")
    
    # Prompt for joke generation
    prompt = """
    You are a helpful AI assistant. Please tell me a funny programming joke.
    """
    
    # Encode the prompt
    inputs = tokenizer(prompt, return_tensors="pt").to('cuda')
    
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