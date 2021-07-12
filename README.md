## Prerequisite
- Docker
- docker-compose
- python >= 3.8
- poetry >= 1.1.4

## Install dependencies

This project uses `poetry` as its package manager. To install dependencies, run

```
poetry install
```

## Development

### poetry

Activate `poetry` env first

```
poetry shell
```

When install new package, need to export `requirements.txt` for circleci to run

```
poetry export --dev -f requirements.txt --output requirements.txt
```

### Production:
export DJANGO_SETTINGS_MODULE=base.settings.production

### Development:

export DJANGO_SETTINGS_MODULE=base.settings.dev


### Start dev
```
cp .env.example .env
docker-compose up -d
./manage.py migrate
./manage.py createsuperuser
./manage.py runserver 0.0.0.0:8000
```

### Start celery worker / beat
```
celery -A base worker --beat -l info
```

## Test
```
./manage.py test
```

### coverage

```
coverage run --omit '.venv/*' --source='.' manage.py test api
coverage html
```