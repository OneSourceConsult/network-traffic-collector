FROM python:3.6-slim-buster AS build


COPY requirements.txt .

RUN pip install --user --no-cache-dir --no-warn-script-location -r requirements.txt

# FROM python:3.8-slim-buster

# COPY --from=build /root/.local /root/.local

WORKDIR /home

COPY collector.py /tmp/collector.py 
# COPY feature_plugin.py /tmp/feature_plugin.py 
# ENV PATH=/root/.local/bin:$PATH

CMD ["python","/tmp/collector.py"]

