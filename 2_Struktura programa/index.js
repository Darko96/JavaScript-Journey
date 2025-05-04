/*
## Izrazi i naredbe

Do sada smo pravili vrednosti i na njih primenjivali operatore da bismo dobili nove vrednosti. Pravljenje takvih vrednostije glavna materija svakog JavaScript programa. Medjutim, ta materija mora bude uokvirena vecom strukturom da bi bila korisna. I to je ono cime cemo se baviti u nastavku.

Deo koda koji proizvodi vrednost naziva se izraz (expression)

Svaka vrednost koja je napisana doslovno  (22 ili “Darko”) jeste izraz. Izraz izmedju zagrada takodje je izraz, a isto vazi i za binarni operator primenjen na dva izraza ili unarni operator primenjen na jedan.

Ako jedan izraz odgovara fragmentu recenice. JavaScriptova naredba (statement) odgovara punoj recenici.

Program je lista naredbi.

Izraz > Naredba > Program

Najednostavnija vrsta naredbe jeste izraz nakon kog stoji tacka i zarez

jsx
1;
!false;

while(izraz) {
	naredba
}


Naredba stoji sama za sebe, pa ima neki znacaj samo ako utice na svet. Ona bi mogla prikazati nesto na ekranu, i to se racuna u menjanje sveta, ili bi mogla da promeni unutrasnje stanje masine na nacin koji ce uticati na naredbe koje slede nakon nje. Te promene se nazivaju sporedna dejstva.

Sporedna dejstva (side effects) su promene koje uticu na naredbe nakon te promene.

Naredbe iz prethodnog primera samo su proizvele vrednost 1 i true, i odmah zatim su ih bacile. To ne ostavlja nikakav utisak. Kada pokrenete ovaj program, ne desava se nista primetno.

## Promenljive

Kako program pamti stvari?

Da bi hvatao i cuvao vrednosti, JavaScript ima nesto sto se naziva vezivanje (binding) ili promenljiva (variable).

jsx
let caught = 5 * 5


To je druga vrsta naredbe(pored izraza). 

Posebna (rezervisana) rec let oznacava da ce ta recenicadefinisati vezivanje. Nakon nje stoji ime promenljive i, ako zelimo odmah da joj dodelimo vrednost, operator = i izraz.

Kada je promenljiva definisana, njeno ime se moze koristiti kao izraz. Vrednost takvog izraza jeste vrednost koju promenljiva trenutno cuva.

jsx
let ten = 10
console.log(ten * ten)
// ➡️ 100


Promenljivu treba da zamisljate vise kao pipke, nego kao kutiju. One ne sadrze vrednosti, one ih samo drze, dve promenljive mogu referencirati istu vrednosti.

Kada definiste promenljivu ne dajuci joj vrednost, pipak nema sta da drzi, pa samo landara u vazduhu. Ako zatrazite vrednost iz prazne promenljive, dobicete vrednost undefined.

Rec const predstavljha konstantu. Ona definise konstantno vezivanje kojim se uvek ukazuje na istu vrednost dokle god ono postoji. To je korisno za promenljive koje daju ime nekoj vrednosti tako da kasnije mozete lakse da je referencirate.

### Imena promenljivih

Imena promenljivih mogu biti bilo koja rec.

Cifre mogu biti deo imena promenljivih ali ime promenljive ne sme da pocne cifrom.

Ime promenljive moze da sadrzi znak za dolar ili donju crtu, ali ne sme nijedan drugi znak interpunkcije ili specijalni znak.

### Okruzenje

Kolekcija promenljivih i njihovih vrednosti koje postoje u datom trenutku naziva se okruzenje (environment)

Kada zapocnete program to okruzenje nije prazno. Ono uvek sadrzi promenljive koje su deo jezickog standarda, a u vecini slucajeva, ima i promenljive koje obezbedjuju nacine za interakciju sa okruzujucim sistemom. Na primer, u citacu postoje funkcije za interakciju sa trenutno ucitanom veb prezentacijom i za citanje unosa preko misa i tastature.

### Funkcije

Mnoge vrednosti koje su obezbedjene u unapred zadatom okruzenju imaju tip funkcija (function)

Funkcija je deo programa unutan u vrednost. Takve vrednosti se mogu primeniti da bi se pokrenuo program umotan u njih.

Na primer, u okruzenju citaca, promenljiva prompt cuva funkciju koja prikazuje mali okvir za dijalog za korisnicki unos. Koristi se ovako:

jsx
prompt("Enter passcode");


Izvrsavanje funkcije se naziva pozivanje (calling, applying)

Funkciju mozete pozvati tako sto cete staviti zagrade nakon izraza koji proizvodi vrednost funkcije.

Vrednosti izmedju zagrada se prosledjuju programu unutar funkcije.

Vrednosti koje se prosledjuju funkcijama nazivaju se argumenti (arguments)

### Console.log

Vecina JavaScript sistema (ukljucujuci sve savremene veb citace i Node.js) obezbedjuje funkciju console.log koja ispisuje svoje argumente na nekom uredjaju za prikazivanje tkest. U citacima, prikaz zavrsava u JavaScriptovoj konzoli.

Iako imena promenljivih ne mogu da sadrze tacku, console.log je ima. Razlog je to sto console.log nije jednostavna promenljiva. Ona je zapravo izraz koji poziva svojstvo log iz vrednosti koju cuva promenljiva console.

### Povratne vrednosti

Prikazivanje okvira za dijalog ili ispisivanje teksta na ekranu jeste sporedno dejstvo. Mnoge funkcije su korisne zbog sporednih dejstava koje imaju.

Funkcije mogu proizvesti i vrednosti i u tom slucaju ne moraju imati sporedno dejstvo da bi bile korisne. Na primer, funkcija Math.max uzima bilo koju kolicinu brojcanih argumenata i vraca najveci.

jsx
console.log(Nath.max(2, 4));
// ➡️ 4


Kada funkcija proizvodi neku vrednosti, kazemo da vraca tu vrednost. Sve sto u JavaScriptu proizvodi vrednost jeste izraz, a to znaci da se pozivi funkcija mogu koristiti unutar vecih izraza.

Ovde se poziv za Math.min, koja je suprotna funkciji Math.max, koristi kao deo izraza za sabiranje:

jsx
console.log(Math.min(2, 4) + 100);
// ➡️ 102


### Tok izvrsavanja

Kada program sadrzi vise od jedne naredbe (skupa izraza do prve tacke i zareza), one se izvrsavaju kao da su prica, od vrha ka dnu. 

Naredni primer programa ima dve naredbe. Prva trazi od korisnika da unese broj, a druga, koja se izvrsava nakon prve, pokazuje kvadrat tog broja.

Funkcija number pretvara vrednostu broj. Ta konverzija nam je potrebna jer prompt za rezultat ima znakovni niz, a nama treba broj.

jsx
let theNumber = Number(prompt("Izaberi broj"));

console.log("Tvoj broj je kvadratni koren broja " + theNumber * theNumber);


### Uslovno izvrsavanje

Nisu svi programi pravi putevi. Na primer, mozda zelimo da napravimo put koji se grana pa ce program krenuti ispravnim krakom puta zavisno od trenutne situacije. To se naziva uslovno izvrsavanje (conditional execution)

Uslovno izvrsavanje se u JavaScriptu pravi pomocu rezervisane reci if. U jednostavnom slucaju, zelimo da neki kod bude izvrsen ako, i samo ako je neki uslov ispunjen.

Na primer. mogli bismo zeleti da prikazemo kvadrat korisnickog unosa samo ukoliko je unos zaista broj.

jsx
let theNumber = Number(prompt("Izabrani broj"));

// is.NaN vraca true ako dobije kao argument nesto sto nije broj
// Number vraca NaN ako dobije kao argument nesto sto nije broj
// Dakle ako ne prosledimo broj onda ce Number vratiti NaN, isNaN ce to gledati kao true
// Zbog toga je potrebno da dodamo logicko NE koje ce 
// zameniti False u True kada unesemo broj
if(!Number.isNaN(theNumber)) {
	console.log("Tvoj broj je kvadrati koren broja " + theNumber * theNumber);
}


Funkcija Number.isNaN standardna je funkcija JavaScripta koja vraca rezultat true ako je argument koji joj je dat NaN. 

Funkcija Number vraca NaN kada joj date znakovni niz koji ne predstavlja ispravan broj.

Vitiacaste zagrade se mogu koristiti za grupisanje bilo kog broja naredbi u jednu naredbu i to se naziva blok (block).

Cesto necete imati samo kod koji se izvrsava kada je uslov tacan, vec i kod koji se bavi onim dreugim slucajem. Ta druga putanja predstavljena je drugom strelicem u dijagramu. Mozete koristiti rezervisanu rec else, zajedno sa if, da biste napravili dve odvojene, alternativne putanje izvrsavanja.

jsx
let theNumber = Number(prompt("Izabrani broj"));

if(!Number.isNaN(theNumber)) {
	console.log("Tvoj broj je kvadrati koren broja " + theNumber * theNumber);
} else {
	console.log("Hej, zasto mi ne dade broj?");


### Petlje while i do

Petlja (loop) je nacin da se vise puta pokrene deo koga. Taj oblik izvrsavanja naziva se petlja.

Tok sa petljom omogucava da se vratimo na neku tacku u programu u kojoj smo ranije bili, i da je ponovimo s tekucim stanjem programa. Ukoliko to kombinujemo sa promenljivom koja broji, mozemo uraditi nesto ovako:

jsx
let number = 0

while(number <= 12) {
	console.log(number);
	number = number + 2;
}
➡️ 0
➡️ 2
➡️ 4
➡️ ... itd


Naredba koja pocinje rezervisanom recju while pravi petlju. Nakon reci while sledi izraz u zagradama i potom naredba, slicno kao za if. Petlja nastavlja da ulazi u naredbu sve ok izraz proizvodi vrednost koja daje true kada se pretvoru u Bulovu vrednost.

Promenljiva number prikazuje nacin na koji promenljiva moze da prati napredovanje programa.

Primer: Program koji izracunava i prikazuje vrednost 2 na 10. Koristimo dve promenljive: jednu koja ce pratiti rezultat i jednu koja ce brojati koliko smo cesto taj rezultat pomnozili sa 2. Petlja proverava da li je druga promenljiva dostigla 10 i, ako nije, azurira obe promenljive.

jsx
let result = 1
let counter = 0

// sve dok je promenljiva counter manja od 10
// - promenljivu result pomnozi sa 2
// - promenljivu counter povecaj za 1
while(counter < 10) {
	result = result * 2;
	counter = counter + 1;
}

console.log(result)
➡️ 1024


Petlja do je struktura toka slicna petlji while. Razlikuje se samo u jednoj stvari: petlja do uvek izvrsava svoje telo bar jednom i pocinje da proverava da li treba da stane tek nakon tog prvog izvrsavanja. Kao odraz toga, provera se nalazi nakon tela petlje.

jsx
let yourName

do {
	yourName = prompt("Ko si ti?");
} while(!yourName);
console.log(yourName);

// Ako unesemo recimo string "Darko", yourName ce biti true, ali zbog 
// logicke negacije koju stvara !, onda prelazi u false i program se zavrsava
// Ako unesem prazak string, to je false vrednost, ali zbog logicke negacije onda prelazi
// u true i zbog toga ce se petlja ponovo pokrenuti


### Uvlacenje koda

Uloga uvlacenja u blokovima je da istakne strukturu koda.

### Petlja for

Mnoge petlje prate obrazan prikazan u primerima za petlju while. 

- Prvo se napravi promenljiva brojaca za pracenje napredovanja petlje.
- Potom sledi petlja while, obicno sa izrazom koji proverava da li je brojac dostigao svoju kranju vrednost.
- Na kraju tela petlje, brojac se azurira da bi se pratilo napredovanje.

Posto je taj obrazan toliko uobicajen, JavaScript i slicni jezici nude nesto kracu i sveobuhvatniju fromu, petlju for.

jsx
for(let number = 0; number <= 12; number = number + 2) {
	console.log(number)
}
➡️ 0
➡️ 2
➡️ 4
➡️ ... itd


Zagrade nakon rezervisane reci for moraju da sadrze dva znaka tacka i zarez. Deo pre prvih tacka i zareza inicijalizuje petlju, obicno definisanjem promenljive. Drugi deo je iraz koji proverava da li petlja mora da nastavi. Poslednji deo azurira stanje petlje nakon svakog ponavljanja. Uvecini slucajeva, to je krace i jasnije od konstrukcije while.

Naredni kod izracunava 2 na 10 koristeci for umesto while.

jsx
let result = 1

for(let counter = 0; counter <= 10; counter = counter + 1) {
	result = result * 2
}

console.log(result)
➡️ 1024


### Raskidanje petlje

Uslov za petlju koji daje false nije jedini nacin da se petlja zavrsi. Postoji posebna naredba nazvana break koja ima dejstvo trenutnog iskakanja iz petlje koja je obuhvata.

jsx
for(let current = 20; ; current = current + 1) {
	if(current % 7 == 0) {
		console.log(current);
		break;
}

➡️ 21
// Petlja krece da proverava da li je ostatak pri deteljenju sa 7 jednak nuli
// posto 20 to nije onda se current povecava za 1 i petlja se nastavlja
// sada ostatak pri deteljenju sa 7 jeste jednak nuli i onda se to ispisuje na ekranu
// i petlja se zavrsava zbog naredbe break


Koriscenje operatora za ostatak deljenja (%) lak je nacin da se proveri da li je neki broj deljiv drugim brojem. Ako jeste, ostatak njihovog deljenja je nula.

Konstrukcija petlje for u primeru nema deo koji proverava kada treba da bude kraj petlje. To znaci da se petlja nikada nece zaustaviti osim ako se ne izvrsi naredba break unutar nje.

Da nema naredbe break ovaj kod bi sadržao **beskonačnu petlju** jer nema eksplicitno definisanog uslova za završetak (for petlja nema drugog izraza između prvog i poslednjeg tačka-zareza).

Rezervisana rec continue slicna je naredbi break po tome sto utice na napredovanje petlje. Kada stigne do continue u telu petlje, tok izvrsavanja iskace iz tela i nastavlja sa sledecim ponavljanjem petlje.

### Kratko i jasno azuriranje promenljive

Narocito kada prolazi kroz petlju, program cesto mora da azuriranje promenljivu tako da cuva vrednost zasnovanu na prethodnoj vrednosti te promenljive.

jsx
counter = counter + 1

// skracena verzija
counter += 1

// najkraca verzija
counter ++


### Slanje vrednosti pomocu switch

Postoji struktura koja se naziva switch i koja sluzi da se ovakvo slanje izrazi na direktniji nacin.

jsx
switch (prompt("Kakvo je vreme?")) {
  case "kisovito":
    console.log("Ne zaboravi kisobran");
    break;
  case "suncano":
    console.log("Obuci nesto lagano");
  case "oblacno":
    console.log("Izadji");
    break;

  default:
    console.log("Nepoznat tip vremena");
    break;
}



U bloku koji otvara rec switch mozete postaviti proizvoljan broj oznaka case (U slucaju) Program ce poceti da se izvrsava u oznaci koja odgovara vednosti koja je data switch, ili ce preci na default ako se ne pronadje odgovarajuca vrednost. Nastavice da se izvrsava, cak i preko drugih oznaka, sve dok ne stigne do naredbe break.

### Velika i mala pocetna slova

Imena promenljivih ne smeju da sadrze razmake, ali cesto je zgodno koristiti vise reci da bi se jasno opisalo sta promenljiva predstavlja.

Standardne JavaScript funkcije i vecina JavaScript programera pridrzava se stilu - svala rec, osim prve, ima veliko pocetno slovo.

### Komentari

Sirovi kod cesto ne prenosi sve informacije koje zelite da program prenese citaocima, ili ih prenosi na tako sifrovan nacin da ga oni mozda nece razumeti. 

Ponekad cete pozeleti i samo da dodate neka povezana razmisljanja kao deo svog programa. Za to sluze komentari.

Komentar (comment) je tekst koji je deo programa, ali ga racunar potpuno zanemruje.

jsx
// linijski komentar

 
viselinijski komentar
/ *  * /


### Rezime

Znate da je program sacinjen od naredbi koje i same mogu sadrzati vise naredbi.

Naredbe obicno sadrze izraze koji mogu biti izgradjeni od manjih izraza.

Radjanje naredbi jedna za drgom daje vam program koji se izvrsava od vrha ka dnu.

Mozete uvesti nemir u tok izvrsavanja koriscenjem uslova (if, else, switch) i ponavljanjem naredbi u petlji (while, do i for)

Promenljive se mogu koristiti za skladistenje delova podataka pod nekim imenom i korisne su za pracenje stanja u programu.

Okruzenje je skup promenljivih koje su definisane.

Funkcije su posebne vrednosti koje kapsuliraju deo programa.
*/

// Vezbe

// Petljom do trougla
let hash = "#";

for (let r = 0; r <= 6; r++) {
  console.log(hash);
  hash += "#";
}

// FIzzBuzz
for (let i = 1; i <= 100; i++) {
  if (i % 5 == 0 && i % 3 == 0) {
    console.log("FizzBuzz");
  } else if (i % 5 == 0) {
    console.log("Buzz");
  } else if (i % 3 == 0) {
    console.log("Fizz");
  } else {
    console.log(i);
  }
}

// Sahovska tabla
let even = "# # # #\n";
let odd = " # # # #\n";

let table = "";

for (let i = 0; i < 8; i++) {
  if (i % 2 == 0) {
    table += even;
  } else {
    table += odd;
  }
}

console.log(table);
