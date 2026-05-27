#!/bin/bash
export CUDA_LAUNCH_BLOCKING=1; python /home/partha9/CS885-RProject/Evaluate_AC_Entropy.py \
--file_path /project/def-m2nagapp/partha9/LTR/ \
--model_path Models/AC/Entropy/AspectJ/AspectJ_AC_Entropy_V2_policy_model_249.0.pt \
--result_path /project/def-m2nagapp/partha9/LTR/Results/AC/Entropy/AspectJ/ \
--test_data_path Data/TestData/AspectJ_test.csv \
--project_name AspectJ
