#!/bin/bash
#SBATCH --job-name=llama70b
#SBATCH --partition=gpu
#SBATCH --gres=gpu:a100:1          # Request 1 A100 GPU
#SBATCH --mem=128G                 # Adjust if needed
#SBATCH --cpus-per-task=8
#SBATCH --time=08:00:00
#SBATCH --account=cs6888-spring25  # <--- This is key
#SBATCH --output=llama70b.out
#SBATCH --error=llama70b.err

# Load modules and activate Conda
module purge
module load anaconda
source activate log4j-llm-fuzzer

# Optional: move to your script directory
cd $SLURM_SUBMIT_DIR

# Run your quantized model
python ./LLM/log4j-llm/llama-joke.py
