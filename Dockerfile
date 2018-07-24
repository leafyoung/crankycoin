FROM python:3
COPY . /
RUN pip install -r 
CMD [ "python", "run.py", "client" ]