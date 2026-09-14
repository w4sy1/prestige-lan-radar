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
