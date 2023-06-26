# -*- coding: utf-8 -*-

#  Copyright 2023 Quarkslab
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import os
import urllib.request
import shutil
import subprocess
from pathlib import Path
from setuptools import setup, Extension
from setuptools.command.build_ext import build_ext
from tempfile import mkdtemp
from zipfile import ZipFile

CURRENT_DIR = Path(__file__).parent
ZIP_URL = 'https://github.com/CoatiSoftware/SourcetrailDB/archive/refs/tags/v4.db25.p1.zip'
EXTRACTION_DIR = Path(mkdtemp())


class ZipCMakeExtension(Extension):
    def __init__(self, name: str) -> None:
        super().__init__(name, sources=[])
        zip_path, header = urllib.request.urlretrieve(ZIP_URL)
        zip_file = ZipFile(zip_path)
        zip_file.extractall(path=EXTRACTION_DIR)
        self.sourcedir = EXTRACTION_DIR.resolve().absolute().joinpath('SourcetrailDB-4.db25.p1')
        urllib.request.urlcleanup()


class CMakeBuild(build_ext):
    def build_extension(self, ext):
        cmake_args = ['-DBUILD_BINDINGS_PYTHON=ON']
        build_args = ['--target', '_bindings_python', '--config', 'Release']

        self.build_temp = Path(self.build_temp)
        if not self.build_temp.exists():
            self.build_temp.mkdir(parents=True)

        env = os.environ.copy()

        try:
            subprocess.check_call(['cmake', f'{ext.sourcedir}'] + cmake_args, cwd=self.build_temp, env=env)
            subprocess.check_call(['cmake', '--build', '.'] + build_args, cwd=self.build_temp)

            shutil.copy2(self.build_temp / 'bindings_python' / 'sourcetraildb.py', self.build_lib)
            if os.name=="nt":
              shutil.copy2(self.build_temp / 'bindings_python' / 'Release' / '_sourcetraildb.pyd', self.build_lib)
            else:
              shutil.copy2(self.build_temp / 'bindings_python' / '_sourcetraildb.so', self.build_lib)
        except Exception as e:
            raise e
        finally:
            shutil.rmtree(EXTRACTION_DIR)
            shutil.rmtree(self.build_temp)


setup(
    ext_modules=[
        ZipCMakeExtension('sourcetraildb')
    ],
    cmdclass=dict(build_ext=CMakeBuild),
    zip_safe=False,
)
