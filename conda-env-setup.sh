#!/bin/bash
# Setup script for Log4j LLM Fuzzing Environment

# Create a new conda environment with Python 3.9
conda create -n log4j-llm-fuzzer python=3.9 -y

# Activate the new environment
conda activate log4j-llm-fuzzer

# Install packages from conda-forge to ensure compatibility
conda install -c conda-forge numpy pandas -y
conda install -c conda-forge pytorch torchvision torchaudio cudatoolkit=11.7 -y
conda install -c conda-forge huggingface_hub transformers -y
conda install -c conda-forge scipy scikit-learn -y

# Install any remaining packages with pip
pip install accelerate
pip install peft
pip install bitsandbytes
pip install sentencepiece
pip install tqdm

# Install Java-related packages for log4j fuzzing
conda install -c conda-forge openjdk=11 -y

# Create the directory for model storage if it doesn't exist
mkdir -p /scratch/$(whoami)/log4j_llm_fuzzing

# Test if the installation works by running a simple import
python -c "from transformers import AutoTokenizer, AutoModelForCausalLM; print('Transformers installed successfully!')"

echo "Setup complete. Use 'conda activate log4j-llm-fuzzer' before running your code."
echo "All models will be stored in /scratch/$(whoami)/log4j_llm_fuzzing"