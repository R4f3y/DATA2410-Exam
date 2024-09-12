# Importerer nødvendige biblioteker
import os
import socket
import argparse
import ipaddress
from struct import *
import time
import sys
import datetime

# Beskrivelse av funksjonen:
# Funksjon for å sjekke gyldigheten av en IP-adresse
# Argumenter:
# ip: Dette er IP-adressen som skal sjekkes
# Funksjonen gjør:
# Den prøver å lage en IP-adresse objekt fra den oppgitte strengen, og hvis det ikke er mulig, genererer den en feil
# Brukes for å sikre at IP-adressen som sendes til serveren er i gyldig format
# Retur: Hvis IP-adressen er gyldig, returneres den. Hvis ikke, kastes en argumentfeil.
def valid_ip(ip):
    try: 
        ipaddress.ip_address(ip)
        return ip
    except ValueError:
        raise argparse.ArgumentTypeError(f"Ugyldig IP adresse: {ip}")

# Beskrivelse av funksjonen:
# Funksjon for å sjekke gyldigheten av et portnummer
# Argumenter:
# port: Dette er portnummeret som skal sjekkes
# Funksjonen gjør:
# Den prøver å konvertere portnummeret til et heltall og sjekker om det er innenfor det gyldige området for portnumre (0-65535)
# Brukes for å sikre at portnummeret som sendes til serveren er i gyldig format
# Retur: Hvis portnummeret er gyldig, returneres det. Hvis ikke, kastes en argumentfeil.
def valid_port(port):
    try:
        port = int(port)
        if 0 <= port <= 65535:
            return port
        else:
            raise argparse.ArgumentTypeError(f"Ugyldig portnummer: {port}. Må være mellom 0 og 65535.")
    except ValueError:
        raise argparse.ArgumentTypeError(f"Ugyldig portnummer: {port}. Må være et tall mellom 0 og 65535.")

# Beskrivelse av funksjonen:
# Funksjon for å sjekke om filen eksisterer og er av gyldig type
# Argumenter:
# file: Dette er banen til filen som skal sjekkes
# Funksjonen gjør:
# Den sjekker først om filen eksisterer. Deretter sjekker den om filen har riktig filtype (jpeg eller jpg)
# Brukes for å sikre at filen som skal sendes eksisterer og er av riktig type
# Retur: Hvis filen er gyldig, returneres filbanen. Hvis ikke, kastes en argumentfeil.
def valid_file(file):
    if not os.path.exists(file):
        raise argparse.ArgumentTypeError(f"Filen {file} finnes ikke.")
    elif not (file.endswith('.jpeg') or file.endswith('.jpg')):
        raise argparse.ArgumentTypeError(f"Ugyldig filtype for {file}. Bare .jpeg eller .jpg filer er tillatt.")
    else:
        return file

# Beskrivelse av funksjonen:
# Funksjon for å sjekke om vindusstørrelsen er gyldig
# Argumenter:
# window_size: Dette er størrelsen på vinduet som skal sjekkes
# Funksjonen gjør:
# Den prøver å konvertere vindusstørrelsen til et heltall og sjekker om det er en positiv verdi
# Brukes for å sikre at vindusstørrelsen som sendes til serveren er gyldig
# Retur: Hvis vindusstørrelsen er gyldig, returneres den. Hvis ikke, kastes en argumentfeil.
def valid_window_size(window_size):
    window_size = int(window_size)
    if window_size <= 0:
        raise argparse.ArgumentTypeError(f"Ugyldig vindusstørrelse: {window_size}. Må være en positiv verdi.")
    else:
        return window_size

# Beskrivelse av funksjonen:
# Funksjon for å analysere kommandolinjeargumenter
# Funksjonen gjør:
# Definerer hva slags argumenter som kan tas inn fra kommandolinjen når programmet kjøres
# Argumenter:
# Ingen argumenter trengs for denne funksjonen siden den bruker argparse biblioteket for å håndtere kommandolinjeargumenter
# Retur: Returnerer argumentene som ble spesifisert når programmet kjørte
def parse_arguments():
    parser = argparse.ArgumentParser(description="DRTP filoverføringsapplikasjon")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-s', '--server', action='store_true', help="Aktiver servermodus")
    group.add_argument('-c', '--client', action='store_true', help="Aktiver klientmodus")
    parser.add_argument('-i', '--ip', type=valid_ip, default='127.0.0.1', help="IP-adressen til serveren (standard: 127.0.0.1)")
    parser.add_argument('-p', '--port', type=valid_port, default=8080, help="Portnummer (standard: 8080)")
    parser.add_argument('-f', '--file', type=valid_file, help="Filbane")
    parser.add_argument('-w', '--window', type=valid_window_size, default=3, help="Størrelsen på skyvevinduet (standard: 3)")
    parser.add_argument('-d', '--discard', type=int, help="Tilpasset testtilfelle for å hoppe over et sekvensnummer")
    return parser.parse_args()
    

# Definer formatet for pakkehodet som '!HHH' for å passe til 16-bits verdier
header_format = '!HHH'

# Definerer flaggene for SYN, ACK, og FIN
SYN = 1
ACK = 2
FIN = 4

# Beskrivelse av funksjonen:
# Funksjon for å lage en pakke med et formatert hode
# Funksjonen gjør:
# Bruker struct.pack for å skape et binært hode
# Argumenter:
# seq: sekvensnummeret for pakken
# ack: bekreftelsesnummeret for pakken
# flags: flaggene for pakken (SYN, ACK, FIN)
# Retur: Returnerer en pakke med formatert hode
def create_packet(seq, ack, flags):
    return pack(header_format, seq, ack, flags)

# Beskrivelse av funksjonen:
# Funksjon for å tolke et pakkehode
# Funksjonen gjør:
# Bruker struct.unpack for å trekke ut sekvensnummeret, bekreftelsesnummeret, og flaggene fra hodet
# Argumenter:
# header: headeren av pakken som skal tolkes
# Retur: Returnerer sekvensnummeret, bekreftelsesnummeret, og flaggene av pakken
def parse_header(header):
    return unpack(header_format, header)

# Server klasse med all server kode
class Server:
    # Beskrivelse av funksjonen:
    # Konstruktøren til Server-klassen.
    # Argumenter:
    # self: Referanse til det aktuelle Server-objektet
    # ip: IP-adressen til serveren
    # port: Portnummeret til serveren
    # file: Filen som skal overføres. Denne parameteren er ikke relevant i servermodus, siden det er server som skal ta imot pakkene og lage en fil ut av det. 
    # Hvis filen (-f) er satt, vil programmet avsluttes med en feilmelding.
    # window_size: Størrelsen på skyvevinduet. I servermodus, er denne parameteren fastsatt til 3, og hvis en annen verdi er valgt, vil programmet avsluttes med en feilmelding.
    # discard: Sekvensnummeret/pakken som skal forkastes for testformål.
    # Funksjonen gjør:
    # Validerer inngangsparameterne, initialiserer variabler for klassen og oppretter en socket for serveren.
    # Brukes for å sette opp serveren med de gitte parameterne
    # Retur: Ingen returverdi for denne funksjonen.
    def __init__(self, ip, port, file, window_size, discard):
        # Validerer inngangsparameterne
        if file:
            print("-s valget kan ikke ta -f argument.")
            sys.exit(1)
        if window_size != 3:
            print("Kun klient (-c) kan endre vindusstørrelsen")
            sys.exit(1)
        
        # Initialiserer variablene for klassen
        self.ip = ip
        self.port = port
        self.discard = int(discard) if discard is not None else None
        #Kjører neste funksjon
        self.sock = self.create_socket()

    # Beskrivelse av funksjonen:
    # Denne metoden oppretter en UDP-socket for serveren.
    # Argumenter: 
    # self: Referanse til det aktuelle Server-objektet
    # Funksjonen gjør:
    # Oppretter en UDP-socket og binder den til den gitte IP-adressen og porten
    # Brukes for å opprette en socket for serveren til å kommunisere med klienten
    # Retur: Dersom alt går bra returneres socketen som ble opprettet, hvis det oppstår noe feil vil dette bli håndtert
    def create_socket(self):
        # Oppretter en UDP-socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # Binder socketen til den gitte IP-adressen og porten
            sock.bind((self.ip, self.port))
        except Exception as e:
            # Håndterer feil ved opprettelse av server socket
            print("Feil ved opprettelse av server socket:", e)
            sock.close()
            sys.exit(1)
        return sock

    # Beskrivelse av funksjonen:
    # Starter serveren og venter på en SYN-pakke fra klienten.
    # Argumenter: 
    # self: Referanse til det aktuelle Server-objektet
    # Funksjonen gjør:
    # Starter serveren og venter på en SYN-pakke fra klienten
    # Brukes for å starte serveren og vente på en SYN-pakke fra klienten for å etablere en forbindelse
    # Retur: Ingen returverdi for denne funksjonen
    def start(self):
        # Starter serveren og venter på SYN-pakken
        print(f'\nServeren kjører med IP-adresse = {self.ip} og portadresse = {self.port}\n')
        #Kjører neste funksjon
        self.receive_syn_packet()

    # Beskrivelse av funksjonen:
    # Venter på og behandler en innkommende SYN-pakke fra klienten.
    # Argumenter: 
    # self: Referanse til det aktuelle Server-objektet
    # Funksjonen gjør:
    # Venter på en SYN-pakke fra klienten og behandler den når den mottas
    # Brukes for å opprette en forbindelse med klienten ved å motta en SYN-pakke
    # Retur: Ingen returverdi for denne funksjonen
    def receive_syn_packet(self):
        # Venter på og behandler en innkommende SYN-pakke
        try:
            packet, address = self.sock.recvfrom(1000)
            seq, ack, flags = parse_header(packet)
            if flags == SYN:
                print("SYN-pakke mottatt")
                #Kjører neste funksjon
                self.send_syn_ack(seq, address)
        #Feilhåndtering
        except socket.timeout:
            print("Socket timeout oppstod under venting på SYN-pakke.")
        except Exception as e:
            print("Feil ved mottakelse av SYN-pakke:", e)

    # Beskrivelse av funksjonen:
    # Sender en SYN-ACK-pakke tilbake til klienten for å etablere forbindelse.
    # Argumenter:
    # self: Referanse til det aktuelle Server-objektet
    # seq: Sekvensnummeret til den mottatte SYN-pakken
    # address: Adressen til klienten
    # Funksjonen gjør:
    # Lager en SYN-ACK-pakke og sender den tilbake til klienten for å etablere en forbindelse (DRTP)
    # Brukes for å bekrefte mottak av SYN-pakken og etablere en forbindelse med klienten
    # Retur: Ingen returverdi for denne funksjonen
    def send_syn_ack(self, seq, address):
        # Sender en SYN-ACK-pakke tilbake til klienten
        self.sock.sendto(create_packet(0, seq+1, SYN | ACK), address)
        print("SYN-ACK-pakke sendt")
        #Kjører neste funksjon
        self.receive_ack()

    # Beskrivelse av funksjonen:
    # Venter på og behandler en innkommende ACK-pakke fra klienten.
    # Argumenter:
    # self: Referanse til det aktuelle Server-objektet
    # Funksjonen gjør:
    # Venter på en ACK-pakke fra klienten og behandler den når den mottas
    # Brukes for å bekrefte etableringen av forbindelsen med klienten
    # Retur: Ingen returverdi for denne funksjonen
    def receive_ack(self):
        # Venter på og behandler en innkommende ACK-pakke
        try:
            packet, address = self.sock.recvfrom(1000)
            seq, ack, flags = parse_header(packet)
            if flags == ACK:
                print("ACK-pakke mottatt")
                #Kjører neste funksjon
                self.receive_data_packets(address, self.discard)
        except socket.timeout:
            print("Socket timeout oppstod under venting på ACK-pakke.")
        except Exception as e:
            print("Feil ved mottakelse av ACK-pakke:", e)

    # Beskrivelse av funksjonen:
    # Mottar data fra klienten, skriver dataene til en fil (Photo_recieved.jpg), og sender en ACK-pakke tilbake til klienten.
    # Argumenter:
    # self: Referanse til det aktuelle Server-objektet
    # address: Adressen til klienten
    # discard: Sekvensnummeret som skal forkastes for testformål
    # Funksjonen gjør:
    # Mottar data fra klienten, skriver dataene til en fil, og sender en ACK-pakke tilbake til klienten for hver mottatt pakke
    # Denne funksjonen bruker også et "discard"-nummer for testformål. Hvis en pakke med dette sekvensnummeret mottas, vil den bli forkastet.
    # Retur: Ingen returverdi for denne funksjonen
    # Unntakshåndtering: Håndterer unntak som kan oppstå under mottak av pakker, inkludert socket timeout på 0.5 sekunder og andre unntak

    def receive_data_packets(self, address, discard):
        # Får stien til den nåværende mappen
        current_dir = os.path.dirname(os.path.abspath(__file__))
        # Legger til filnavnet til stien
        filename = os.path.join(current_dir, 'Photo_received.jpg')
        # Oppretter en ny fil i den nåværende mappen for å lagre mottatt data
        file = open(filename, 'wb')
        # Initialiserer variabler for å beregne gjennomstrømningen
        start_time = time.time()
        total_bytes = 0
        # Forventet sekvensnummer
        expected_seq = 1
        # Siste sekvens skrevet til filen
        last_written_seq = 0
        discard_done = False
        # Hovedserverløkke
        while True:
            try:
                # Mottar data fra socket, henter avsenderens adresse og parserer pakkeheaderen for sekvensnummer, bekreftelsesflagg og flagg
                data, address = self.sock.recvfrom(1000)
                seq, ack, flags = parse_header(data[:6])

                # Hvis sekvensnummeret er det vi forventer
                if seq == expected_seq:
                    # Hvis sekvensnummeret er lik self.discard og vi ikke allerede har forkastet en pakke
                    if seq == self.discard and not discard_done:
                        # Informer om at pakken er forkastet
                        print(f"{datetime.datetime.now().strftime('%H:%M:%S.%f')} -- Pakke {seq} ble forkastet")
                        discard_done = True  # Oppdater flagget for å indikere at vi har forkastet en pakke
                        
                        continue  # Fortsett til neste iterasjon av løkken uten å behandle den forkastede pakken

                    # Hvis sekvensnummeret ikke er lik self.discard, behandles pakken som vanlig
                    print(f"{datetime.datetime.now().strftime('%H:%M:%S.%f')} -- Pakke {seq} er mottatt")
                    file.write(data[6:])
                    total_bytes += len(data) - 6
                    last_written_seq = seq  # Oppdaterer den siste sekvens som ble skrevet
                    expected_seq += 1

                    print(f"{datetime.datetime.now().strftime('%H:%M:%S.%f')} -- Sender ack for den mottatte {last_written_seq}")  # Sender ACK for den siste skrevne sekvens
                    self.sock.sendto(create_packet(0, expected_seq, ACK), address)

                # Hvis pakken har et høyere sekvensnummer enn forventet
                elif seq > expected_seq:
                    print(f"{datetime.datetime.now().strftime('%H:%M:%S.%f')} -- Uordnet pakke {seq} er mottat")
                    continue  # Fortsett til neste iterasjon av løkken uten å behandle den ut-av-rekkefølge-pakken
                            
                
                if flags == FIN:
                    print("\nFIN-pakke mottatt")
                    #Kjører neste funksjon
                    self.send_fin_ack(seq, address)
                    break
            except socket.timeout:
                print("Socket timeout oppstod under venting på en pakke.")
            except Exception as e:
                print("Feil ved mottakelse av pakke:", e)
                sys.exit(1)
        # Beregner og skriver ut gjennomstrømningen
        throughput = total_bytes / (time.time() - start_time) * 8 / 1e6
        print(f"Gjennomstrømningen er {throughput:.2f} Mbps")
        # Lukker tilkoblingen og avslutter programmet
        self.sock.close()
        print("Forbindelsen er avsluttet")
        sys.exit(1)

    # Beskrivelse av funksjonen:
    # Sender en FIN-ACK-pakke tilbake til klienten for å avslutte forbindelsen.
    # Argumenter:
    # self: Referanse til det aktuelle Server-objektet
    # seq: Sekvensnummeret til den mottatte FIN-pakken
    # address: Adressen til klienten
    # Funksjonen gjør:
    # Lager en FIN-ACK-pakke og sender den tilbake til klienten for å avslutte forbindelsen
    # Brukes for å bekrefte mottak av FIN-pakken og avslutte forbindelsen med klienten
    # Retur: Ingen returverdi for denne funksjonen
    def send_fin_ack(self, seq, address):
        # Sender en FIN-ACK-pakke tilbake til klienten
        self.sock.sendto(create_packet(0, seq+1, ACK), address)
        print("FIN ACK-pakke sendt\n")
        
# Klientklasse med all kode for klient
class Client:

    # Beskrivelse av funksjonen:
    # Initialiserer en ny klientinstans
    # Argumenter:
    # self: Referanse til det aktuelle Client-objektet
    # ip: IP-adressen til serveren
    # port: Portnummeret til serveren
    # file: Filbanen til filen som skal sendes
    # window_size: Størrelsen på skyvevinduet
    # discard: Parameter for å forkaste pakker (ikke brukt i kontrollinjeargumentene for klient)
    # Funksjonen gjør:
    # Validerer inputargumentene og initialiserer klientobjektet
    # Retur: Ingen returverdi for denne funksjonen
    def __init__(self, ip, port, file, window_size, discard):
        # Sjekker om filbanen er gitt
        if not file:
            print("Feil: Filbane er nødvendig i klientmodus.")
            sys.exit(1)
        # Sjekker om discard-argumentet er gitt
        if discard:
            print("Feil: -c valget kan ikke ta -d argumentet.")
            sys.exit(1)
        # Setter objektvariablene
        self.ip = ip
        self.port = port
        self.file = file
        self.window_size = window_size
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(0.5)

    # Beskrivelse av funksjonen:
    # Starter tilkoblingsprosessen til serveren
    # Argumenter:
    # self: Referanse til det aktuelle Client-objektet
    # Funksjonen gjør:
    # Prøver å koble til serveren og sender en SYN-pakke til serveren for å initiere forbindelsen
    # Retur: Ingen returverdi for denne funksjonen
    def connect(self):
        # Prøver å koble til serveren
        try:
            self.sock.connect((self.ip, self.port))
            print("\nFase for etablering av forbindelse:\n")
            # Sender en SYN-pakke til serveren for å initiere forbindelse
            self.send_syn_packet()
        except ConnectionRefusedError:
            print(f"Feil: Tilkobling nektet. Serveren er ikke tilgjengelig på {self.ip}:{self.port}")
            self.sock.close()
        except Exception as e:
            print("Feil ved oppretting av klient socket:", e)
            self.sock.close()

    # Beskrivelse av funksjonen:
    # Sender en SYN-pakke til serveren
    # Argumenter:
    # self: Referanse til det aktuelle Client-objektet
    # Funksjonen gjør:
    # Sender en SYN-pakke til serveren og venter på en SYN-ACK-pakke fra serveren
    # Retur: Ingen returverdi for denne funksjonen
    def send_syn_packet(self):
        self.sock.sendto(create_packet(0, 0, SYN), (self.ip, self.port))
        print("SYN-pakke er sendt")
        # Mottar en SYN-ACK-pakke fra serveren
        self.receive_syn_ack()

    # Beskrivelse av funksjonen:
    # Mottar en SYN-ACK-pakke fra serveren
    # Argumenter:
    # self: Referanse til det aktuelle Client-objektet
    # Funksjonen gjør:
    # Venter på en SYN-ACK-pakke fra serveren og sender en ACK-pakke tilbake når den mottas
    # Retur: Ingen returverdi for denne funksjonen
    def receive_syn_ack(self):
        # Prøver å motta en SYN-ACK-pakke fra serveren
        try:
            data, server = self.sock.recvfrom(1000)
            _, ack, flags = parse_header(data[:6])
            if flags == (SYN | ACK):
                print("SYN-ACK pakke er mottatt")
                # Sender en ACK-pakke til serveren
                self.send_ack_packet()

        except socket.timeout:
            print("Timeout oppstod, mislykket tilkoblingsforsøk")
            self.sock.close()
        except Exception as e:
            print("Feil ved mottak av SYN-ACK pakke fra serveren:", e)
            self.sock.close()

    # Beskrivelse av funksjonen:
    # Sender en ACK-pakke til serveren
    # Argumenter:
    # self: Referanse til det aktuelle Client-objektet
    # Funksjonen gjør:
    # Sender en ACK-pakke til serveren og starter filoverføringen
    # Retur: Ingen returverdi for denne funksjonen
    def send_ack_packet(self):
        self.sock.sendto(create_packet(0, 0, ACK), (self.ip, self.port))
        print("ACK-pakke er sendt")
        print("Forbindelse etablert\n")
        # Starter filoverføring
        self.transfer_file()

    # Beskrivelse av funksjonen:
    # Overfører en fil til serveren
    # Argumenter:
    # self: Referanse til det aktuelle Client-objektet
    # Funksjonen gjør:
    # Lese fildataene og sender dem til serveren i pakker. Hvis en pakke ikke blir bekreftet innen en viss tid (0.5 sekunder), sendes pakken på nytt
    # Retur: Ingen returverdi for denne funksjonen
    def transfer_file(self):
        print("Dataoverføring:\n")
        # Initialiserer skyvevinduet og sekvensnummeret
        window = []
        seq = 1
        sent_time = {}  # Holder styr på når hver pakke ble sendt
        packet_data = {}  # Lagrer data for hver pakke
        self.timeout = 0.5  # Setter timeout-verdien

        # Hovedklientløkke
        # Åpner filen og leser dataene
        with open(self.file, 'rb') as f:
            while True:
                # Hvis vinduet ikke er fullt, leses mer data fra filen og sendes
                while len(window) < self.window_size:
                    data = f.read(994)
                    if not data:
                        break
                    self.sock.sendto(create_packet(seq, 0, 0) + data, (self.ip, self.port))
                    sent_time[seq] = time.time()  # Lagrer tiden pakken ble sendt
                    packet_data[seq] = data  # Lagrer data for pakken
                    window.append(seq)
                    print(f"{datetime.datetime.now().strftime('%H:%M:%S.%f')} -- Pakke med sekvensnummer = {seq} er sendt, skyvevindu = {window}")
                    seq += 1
                if not window:
                    print("Dataoverføring fullført\n")
                    print("Nedbryting av forbindelse:\n")
                    self.send_fin_packet()
                    break
                try:
                    # Venter på en ACK-pakke fra serverens
                    data, server = self.sock.recvfrom(1000)
                    _, ack, flags = parse_header(data[:6])
                    if flags == ACK:
                        # Hvis en ACK-pakke mottas, fjernes det tilsvarende sekvensnummeret fra vinduet
                        if ack - 1 in window:
                            print(f"{datetime.datetime.now().strftime('%H:%M:%S.%f')} -- ACK for pakke = {ack - 1} er mottatt")
                            window.remove(ack - 1)
                except socket.timeout:
                    print(f"{datetime.datetime.now().strftime('%H:%M:%S.%f')} -- Timeout oppstod, sender alle pakker i vinduet på nytt")
                    print(f"{datetime.datetime.now().strftime('%H:%M:%S.%f')} -- RTO oppstod")
                    for seq_num in window:
                        # Sjekker om det har gått nok tid for en retransmisjon
                        if time.time() - sent_time[seq_num] > self.timeout:
                            print(f"{datetime.datetime.now().strftime('%H:%M:%S.%f')} -- Sender pakke med sekvensnummer = {seq_num} på nytt")
                            self.sock.sendto(create_packet(seq_num, 0, 0) + packet_data[seq_num], (self.ip, self.port))  # Sender korrekt data på nytt
                            sent_time[seq_num] = time.time()  # Oppdaterer sendetiden for pakken

    # Beskrivelse av funksjonen:
    # Sender en FIN-pakke til serveren
    # Argumenter:
    # self: Referanse til det aktuelle Client-objektet
    # Funksjonen gjør:
    # Sender en FIN-pakke til serveren for å initiere nedbrytingen av forbindelsen
    # Retur: Ingen returverdi for denne funksjonen
    def send_fin_packet(self):
        self.sock.sendto(create_packet(0, 0, FIN), (self.ip, self.port))
        print("FIN-pakke er sendt")
        # Mottar en FIN ACK-pakke fra serveren
        self.receive_fin_ack()

    # Beskrivelse av funksjonen:
    # Mottar en FIN ACK-pakke fra serveren
    # Argumenter:
    # self: Referanse til det aktuelle Client-objektet
    # Funksjonen gjør:
    # Venter på en FIN ACK-pakke fra serveren og avslutter forbindelsen når den mottas
    # Retur: Ingen returverdi for denne funksjonen
    def receive_fin_ack(self):
        # Prøver å motta en FIN ACK-pakke fra serveren
        try:
            data, server = self.sock.recvfrom(1000)
            _, ack, flags = parse_header(data[:6])
            if flags == ACK:
                print("FIN ACK pakke er mottatt")
                # Avslutter forbindelsen
                self.close_connection()
        except socket.timeout:
            print("Timeout oppstod, mislykket nedbryting av forbindelsen")
            self.sock.close()
        except Exception as e:
            print("Feil ved mottak av FIN ACK pakke fra serveren:", e)
            self.sock.close()

    # Beskrivelse av funksjonen:
    # Avslutter forbindelsen til serveren
    # Argumenter:
    # self: Referanse til det aktuelle Client-objektet
    # Funksjonen gjør:
    # Lukker socketforbindelsen og avslutter programmet
    # Retur: Ingen returverdi for denne funksjonen
    def close_connection(self):
        print("Forbindelse avsluttet")
        self.sock.close()
        sys.exit(1)

# Beskrivelse av funksjonen:
# Hovedfunksjonen til programmet.
# Argumenter:
# Ingen argumenter tas inn i denne funksjonen.
# Hva funksjonen gjør:
# Funksjonen leser kommandolinjeargumentene, initialiserer en server- eller klientinstans basert på disse argumentene, og starter deretter serveren eller klienten.
# Hvis verken server- eller klientmodus er spesifisert, skriver den ut en feilmelding og avslutter programmet.
# Bruk av inn- og ut-parametere i funksjonen:
# Argumentene leses ved hjelp av `parse_arguments`-funksjonen som returnerer et objekt med alle argumentene som attributter.
# Avhengig av disse argumentene, blir enten en server eller en klient opprettet og startet.
# Retur:
# Denne funksjonen returnerer ikke noe fordi dens hovedoppgave er å starte serveren eller klienten basert på argumentene.
# Korrekt håndtering av unntak:
# Hvis verken server- eller klientmodus er spesifisert, skriver funksjonen ut en feilmelding og avslutter programmet med en feilstatus.
def main():
    # Kaller på funksjonen `parse_arguments` som returnerer argumentene som er spesifisert når programmet kjører
    args = parse_arguments()

    # Sjekker om servermodus er spesifisert
    if args.server:
        # Oppretter en serverinstans med de gitte argumentene
        server = Server(args.ip, args.port, args.file, args.window, args.discard)
        # Starter serveren
        server.start()
    # Sjekker om klientmodus er spesifisert
    elif args.client:
        # Oppretter en klientinstans med de gitte argumentene
        client = Client(args.ip, args.port, args.file, args.window, args.discard)
        # Starter klienten
        client.connect()
    else:
        # Hvis verken server- eller klientmodus er spesifisert, skrives en feilmelding ut og programmet avsluttes
        print("Feil: Vennligst spesifiser enten servermodus (-s) eller klientmodus (-c).")
        sys.exit(1)

# Sjekker om dette scriptet ble kjørt direkte (i stedet for å bli importert som et modul)
if __name__ == "__main__":
    # Hvis scriptet ble kjørt direkte, kaller den på hovedfunksjonen
    main()
    