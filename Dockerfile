FROM docker.io/library/python:3.11
SHELL ["/bin/bash", "-c"]

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y python3-pip cmake

ENV PYRRHA_INSTALL_DIR=/tmp/pyrrha
RUN mkdir -p $PYRRHA_INSTALL_DIR

WORKDIR ${PYRRHA_INSTALL_DIR}
COPY dependencies dependencies/
COPY src src/
COPY setup.py ./
COPY pyproject.toml ./

RUN python3 -m venv $HOME/venv
RUN source $HOME/venv/bin/activate

RUN python3 -m pip install -U pip
RUN python3 -m pip install .

WORKDIR /tmp/pyrrha
RUN rm -rf $PYRRHA_INSTALL_DIR

ENTRYPOINT ["pyrrha"]
