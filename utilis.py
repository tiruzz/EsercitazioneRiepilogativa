import requests

def visualizza():
    response = requests.get('http://api.open-notify.org/astros.json')
    data = response.json()
    return data.get("people", [])