FROM instrumentisto/geckodriver:debian

COPY requirements.txt .
COPY app.py .
RUN mkdir /templates
COPY templates/index.html /templates/
COPY templates/channels.html /templates/

RUN apt-get update
RUN apt-get install -y python3 python3-pip python3-flask python3-bs4 python3-requests
RUN python3 -m pip install -r requirements.txt

EXPOSE 4444
EXPOSE 5000

ENV FIREFOX_BINARY=/opt/firefox/firefox

ENTRYPOINT ["bash"]
CMD ["-c", "FIREFOX_BINARY=/opt/firefox/firefox python3 -m flask run --host 0.0.0.0"]
