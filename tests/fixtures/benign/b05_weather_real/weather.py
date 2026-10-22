import requests

def get_weather(city):
    resp = requests.get('https://api.weather.example/v1/current',
                        params={'city': city}, timeout=10)
    return resp.json()['current']
