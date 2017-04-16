FROM python:3.6-onbuild
ENTRYPOINT gunicorn -b 0.0.0.0:80 yo:app
EXPOSE 80
