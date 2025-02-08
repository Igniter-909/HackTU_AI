import os
from pathlib import Path
import logging

logging.basicConfig(level=logging.INFO,format='[%(asctime)s] %(message)s:')

project_name = "HackTU"

list_of_files = [
    f"src/{project_name}/__init__.py",
    f"src/{project_name}/components/__init__.py",
    f"src/{project_name}/utils/common.py",
    f"src/{project_name}/utils/__init__.py",
    f"src/{project_name}/logging/__init__.py",
    f"src/{project_name}/pipeline/__init__.py",
    f"src/{project_name}/constants/__init__.py",
    "app.py",
    "requirements.txt",
    "setup.py",
]

for filePath in list_of_files:
    filePath = Path(filePath)
    filedir,filename = os.path.split(filePath)
    if filedir != "":
        os.makedirs(filedir,exist_ok=True)
        logging.info(f"Created directory: {filedir}")
    if(not os.path.exists(filePath) or (os.path.getsize(filePath) == 0)):
        with open(filePath, 'w') as file:
            logging.info(f"Created file: {filePath}")
    else:
        logging.info(f"File already exists: {filePath}")