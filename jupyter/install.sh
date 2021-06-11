#!/bin/bash

brew update && brew doctor
#brew upgrade
#brew install pyenv
#pyenv versions
#echo 'eval "$(pyenv init -)"' >> ~/.bash_profile
brew install python3
brew install jupyterlab
brew install pip3
pip3 install ipykernel
pip3 install bash_kernel
python -m bash_kernel.install
