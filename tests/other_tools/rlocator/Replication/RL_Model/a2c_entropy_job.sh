#!/bin/bash
export CUDA_LAUNCH_BLOCKING=1; python /home/partha9/CS885-RProject/AC_Entropy.py \
--file_path /project/def-m2nagapp/partha9/LTR/ \
--cache_path /scratch/partha9/.buffer_cache_ac_aspectj \
--train_data_path Data/TrainData/Bench_BLDS_Aspectj_Dataset.csv \
--save_path /project/def-m2nagapp/partha9/LTR/Models/AC/Entropy/AspectJ/ \
--start_from 0 \
--project_name AspectJ
