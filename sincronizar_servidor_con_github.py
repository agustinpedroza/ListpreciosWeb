cd /cloudclusters/ListPrecios
git fetch --all
git reset --hard origin/master
git pull
source ../venv3.10/bin/activate
python app.py