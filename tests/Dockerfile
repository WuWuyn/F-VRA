FROM nvidia/cuda:12.1.1-cudnn8-runtime-ubuntu22.04

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3.10 python3.10-venv python3-pip \
        openjdk-8-jdk-headless \
        git ca-certificates curl \
    && ln -sf /usr/bin/python3.10 /usr/bin/python \
    && rm -rf /var/lib/apt/lists/*

ENV JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64
ENV PATH="$JAVA_HOME/bin:$PATH"

WORKDIR /workspace/app

COPY requirements.txt ./
RUN pip install --upgrade pip && pip install -r requirements.txt

RUN python -m nltk.downloader -d /usr/local/share/nltk_data \
        punkt punkt_tab stopwords wordnet omw-1.4 averaged_perceptron_tagger
ENV NLTK_DATA=/usr/local/share/nltk_data
ENV HF_HOME=/workspace/hf_cache

# The bundled javaParser jars are compiled for Java 11 (class file version 55),
# so Java 11 must take precedence over the Java 8 installed above.
RUN apt-get update && apt-get install -y --no-install-recommends \
        openjdk-11-jdk-headless \
    && rm -rf /var/lib/apt/lists/*
ENV JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64
ENV PATH="$JAVA_HOME/bin:$PATH"

COPY . .

CMD ["python", "entry_tool.py"]
