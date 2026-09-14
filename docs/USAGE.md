# Użycie

`python app.py observe --database lan.sqlite` — odczyt cache sąsiadów, bez sond.
`python app.py observe --input hosts.json --complete` — pełna obserwacja dostarczona przez użytkownika.
`python app.py list` / `python app.py history`
`python app.py tag --mac 00:11:22:33:44:55 --category IoT`
Wejście: lista `[{"ip":"192.168.1.2","mac":"00:11:22:33:44:55","hostname":"router","vendor":""}]`.

Backend: PowerShell Windows / ip Linux. Import i SQLite działają niezależnie.
MVP obserwuje IPv4, nie wykonuje aktywnego discovery. Cache nie gwarantuje stanu online.
Nieobecność daje offline tylko przy świadomym oznaczeniu pełnego importu.
MAC jest identyfikatorem heurystycznym: randomizacja i ponowne użycie IP mogą dawać
pozorne zmiany. Vendor i hostname pochodzą z importu, nie są wysyłane do zewnętrznych baz.

## Rozszerzenia 0.2.0

`python app.py discover --cidr 192.168.1.0/24 --authorized --database lan.sqlite`
wykonuje sondy ICMP do maksymalnie 256 adresów prywatnej podsieci RFC1918.
`--resolve-names` włącza reverse DNS; `--oui oui.json` dodaje producenta z własnej bazy
w formacie `{ "001122": "Producent" }`. Adres lokalny/losowy nie identyfikuje producenta.
Brak odpowiedzi ICMP nie oznacza offline. Discovery nie ustawia `complete`; odpowiedzi
bez dostępnego MAC raportuje osobno. Zniknięcia wymagają wiarygodnego pełnego importu.
Nie uruchomiono aktywnego skanowania prawdziwej sieci w ramach testów deweloperskich.
