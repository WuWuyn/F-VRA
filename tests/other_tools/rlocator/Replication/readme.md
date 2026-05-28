## Requirements: 

1. Install Python (version >= 3).
2. Install Git (version >= 2).
3. Install all the packages listed in the ``requirements.txt`` file.

## Downloading Data

1. Download the data from https://figshare.com/articles/dataset/The_dataset_of_six_open_source_Java_projects/951967. [provided by Ye et al. 2014]
2. Unzip data.
3. Update the ``path`` variable in DataFormatter.ipynb. This variable should point to the unzipped data.
4. Change the ``project`` variable and run all cells for every project.

## Train A2C with Entropy model
Run the script ``RL_model/a2c_entropy_job.sh`` to train the model. Change the ``project_name`` variable to train a model for a different project.

## Train A2C without Entropy model
Run the script ``RL_model/a2c_without_entropy_job.sh`` to train the model. Change the ``project_name`` variable to train a model for a different project.

## Model Evaluation
Run ``RL_model/a2c_evaluate_entropy_job.sh`` to evaluate A2C with entropy models and ``RL_model/a2c_evaluate_without_entropy_job.sh`` to evaluate A2C without entropy models.

## Estimation of the performance lower limit
Run ``bound_estimation_job.sh`` to estimate the lower bound of performance.

## Train XGBoost Model

Run ``Predictor_model.ipynb`` for training and evaluating the xgboost model.

## BM25 variants performance analysis
1. Run ``GetDistro.py``.
2. Run ``BenchmarkCalc.py``.
3. Run ``BM25_variants_performance_analysis.ipynb``