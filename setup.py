import shutil
import subprocess
from pathlib import Path
from setuptools import setup, Extension
from setuptools.command.build_ext import build_ext
from tempfile import mkdtemp
from zipfile import ZipFile

CURRENT_DIR = Path(__file__).parent
ZIP_PATH = CURRENT_DIR / 'dependencies' / 'SourcetrailDB-4.db25.p1.zip'
EXTRACTION_DIR = Path(mkdtemp())


class ZipCMakeExtension(Extension):
    def __init__(self, name: str) -> None:
        super().__init__(name, sources=[])
        zip_file = ZipFile(ZIP_PATH)
        zip_file.extractall(path=EXTRACTION_DIR)
        self.sourcedir = EXTRACTION_DIR.resolve().absolute().joinpath('SourcetrailDB-4.db25.p1')


class CMakeBuild(build_ext):
    def build_extension(self, ext):
        cmake_args = ['-DBUILD_BINDINGS_PYTHON=ON']
        build_args = ['--target', '_bindings_python']

        self.build_temp = Path(self.build_temp)
        if not self.build_temp.exists():
            self.build_temp.mkdir(parents=True)

        try:
            subprocess.check_call(['cmake', f'{ext.sourcedir}'] + cmake_args, cwd=self.build_temp)
            subprocess.check_call(['cmake', '--build', '.'] + build_args, cwd=self.build_temp)

            shutil.copy2(self.build_temp / 'bindings_python' / 'sourcetraildb.py', self.build_lib)
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
