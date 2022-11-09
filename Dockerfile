FROM instrumentisto/geckodriver:debian

COPY requirements.txt .
COPY app.py .
COPY templates .

RUN apt-get update
RUN apt-get install -y python3 python3-pip python3-flask python3-bs4
RUN python3 -m pip install -r requirements.txt

EXPOSE 4444
EXPOSE 5000

ENTRYPOINT ["bash"]
CMD ["-c", "python3 -m flask run"]
