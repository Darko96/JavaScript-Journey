/*
Funkcije su vitalni elementi programiranje u JavaScriptu. Koncept obavijanja dela programa u jednu vrednost ima mnogo namena. Pruza nam nacin da struktuiramo vece programe, da smanjimo ponavljanja, da povezujemo imena s podprogramima i da izolujemo te podprograme jedan od drugog.

### Definisanje funkcije

Definicija funkcije je obicna promenljiva cija je vrednost funkcija.

Na primer, naredni kod definise square tako da se odnosi na funkciju koja izracunava kvadrat datog broja.

jsx
const square = function(x) {
	return x * x;
};

console.log(square(2));
// ➡️ 144


Funkcija se pravi od izraza na cijem pocetku stoji rezervisana rec function.

Funkcije imaju skup parametara (u ovom slucaju samo x) i telo sa naredbama koje ce biti izvrsene kada se funkcija pozove.

Funkcija moze da ima vise parametara ili da ih uopste nema.

U narednom primeru, make Noise ne navodi nijedno ime parametra, dok power navodi dva:

jsx
const makeNoise = function() {
	console.log("Pling!");
};

makeNoise();
// ➡️ Pling!


jsx
const power = function(base, exponent) {
	let result = 1;
	for (let count = 0; count < exponent; count++) {
		result *= base;
	}
	return result;
};

console.log(power(2, 10));
// ➡️ 1024


Neke funkcije proizvode vrednost kao sto cini power i square, a neke ne, kao makeNoise ciji je jedini rezultat sporedno dejstvo.

Naredba return odredjuje vrenost koju funkcija vraca. Kada tok izvrsavanja naidje na takvu naredbu, on odmah iskace iz tekuce funkcije i vracenu vrednost daje kodu koji je pozvao funkciju.

Rezervisana rec return nakon koje ne sledi izraz dovesce do toga da funckija vrati undefined.

Funkcije koje uopste nemaju naredbu return, prosto vracaju undefined.

Parametri funkcije ponasaju se kao obicne promenljive, ali njhove pocetne vrednosti daje pozivalac funkcije a ne kod u samoj funkciji.

### Promenljive i opseg vidljivosti

Svaka promenljiva ima opseg vidljivosti (scope) tj deo programa u kojem je promenljiva vidljiva. 

Za promenljive koje su definisane izvan funkcije ili bloka, opseg vidljivosti je ceo program, mozete ih referencirati kad god pozelite. To su globalne promenljive.

Promenljive napravljene za parametre funkcije ili one koje su deklarisane unutar funkcije mogu se referencirati samo u toj funkciji, pa su poznate kao lokalne promenljive.

Svaki put kada funkcija bude pozvana, prave se nove instance tih promenljivih. Dakle svaki poziv za funkciju dejstvuje u sopstvenom malom svetu.

Promenljive let i const zapravo su lokalne za blok u kojem su deklarisane, pa ako takvu promenljivu napravite u petlji, kod pre i nakon petlje ne moze da je vidi.

U JavaScriptu pre 2015 samo su funkcije pravile nove opsege vidljivosti, pa su starinske promenljive, pravljene pomocu rezervisane reci var, divljive u celoj funkciji u kojoj se javljaju ili u celom globalnom opsegu, ako se ne nalaze u funkciji.

jsx
let x = 10;
if (true) {
  let y = 20;
  var z = 30;
  // x je globalna - vidljiva
  // y i z su kreirane unutar ovog bloka pa su vidljive
  console.log(x + y + z);
}

// x je globalna
// z (var) je vidljiva samo unutar funkcije u kojoj je kreirana
// ili u celom programu
// zato je 10 + 30 = 40
console.log(x + z);


Svaki opseg moze da pogleda u opseg pored njega, pa je promenljiva x vidljiva unutar bloka u prethodnom primeru.

Izuzetak je situacija kada vise promenljivih ima isto ime - u tom slucaju, kod moze da vidi samo onu koja se nalazi najdubolje u sredini. Na primer, kada kod u funkciji halve referencira n, on vidi sopstveno n, ne globalno n.

jsx
const halve = function(n) {
	return n / 2;
}

let n = 10;
console.log(halve(100));
➡️ 50 
// Kada postoje dve promenljive sa istim imenom, gleda se ona promenljiva koja se nalazi
// u najblizem scope-u, ovde je n parametar funkcije gde se koristi pa je mnogo blizi
// nego globalna promenljiva n
console.log(n)
➡️ 10
// Ovde je globalna promenljiva n bliza nego ona sto se nalazi unutar funkcije halve


### Ugnezdjeni opseg

JavaScript ne razlikuje samo globalne i lokalne promenljive. Blokovi i funkcije mogu se praviti unutar drugih blokova i funkcija i tako nastaje vise slojeva lokalnosti.

Svaki lokalni opseg moze da vidi i svoje lokalne opsege koji ga sadrze, i svi opsezi mogu da vide globalni opseg. Taj pristup vidljivosti promenljivih naziva se leksicki opseg (lexical scoping).

jsx
function sabrati(a) {
	// Kod unutar funkcije operacija moze da vidi promenljivu a iz spoljasnje funkcije
	// Ali promenljiva b nije vidljiva u spoljnoj funkciji
  function operacija(b) {
    return a + b;
  }
  return operacija(10);
}

console.log(sabrati(10));


### Funkcije kao vrednost

Promenljiva u funkciji obicno sluzi samo kao ime za odredjeni deo programa.

Vrednost funkcije moze da radi sve sto i druge vrednosti mogu - mozete je koristiti u proizvoljnim izrazima, niste ograniceni samo na pozivanje.

Moguce je uskladistiti vrednost funkcije novoj promenljivoj, proslediti je kao argument nekoj funkciji.

Promeljiva koja cuva funkciju samo je jos jedna obicna promenljiva i mozete joj, ako nije konstanta, dodeliti novu vrednost.

### Notacija deklaracije

Postoji neznatno kraci nacin pravljenja promenljive sa funkcijom. Kada se kljucna rec function koristi na pocetku naredbe, ona radi drugacije.

jsx
function square(x) {
  return x * x;
}


Deklaracija funkcije - naredba definise promenljivu square i sumerava je na datu funkciju. 

Deklaracije funkcije nisu deo uobicajenog toka izvrsavanja od vrha ka dnu. One su konceptualno promestene na vrh svog opsega i moze ih koristiti sav kod u tom opsegu. To je ponekad korisno jer nudi slobodu redjanja koda na nacin koji je smislen, bez briga o obaveznom definisanju svih funkcija pre nego sto budu upotrebljene.

jsx
console.log("Buducnost kaze:", future());

function future() {
	return "Nikada necete imati letece automobile";


### Strelicaste funkcije

Postoji i treca notacija za funkcije i ona izgleda savim drugacije od ostalih.

Umesto rezervisane reci function, ona koristi strelicu (=>) napravljenu od znaka jednakosti i znaka vece od.

Strelica se pise nakon liste parametara i nakon nje sledi telo funkcije. Ona izrazava nesto kao: ovaj unos (parametri) daje ovaj rezultat (telo).

Ukoliko telo cini jedan izraz, a ne blok u viticastim zagradama, funkcija ce vratiti taj izraz. Znaci, ove dve definicije za square rade istu stvar:

jsx
const square2 = (x) => { return x * x;};

const square2 = x => x * x;


Kada strelicasta funkcija uopste nema parametre, njega lista parametara bice samo prazan par zagrada.

jsx
const horn = () => {
	console.log("Toot";
}


### Stek poziva

Nacin na koji izvrsavanje tece kroz funkcije donekle je slozen. Pogledajmo ga pazljivije. Evo jednostavnog programa koji pravi nekoliko poziva za funkcije.

jsx
1 function greet(who) {
2 	console.log("Hello " + " who);
3 }
4
5 greet("Harry");
6 console.log("Bye");


Prolazak kroz ovaj program tece otprilike ovako:

- poziv za greet tera tok izvrsavanja da skoci na pocetak te funkcije (red 2)
- Funkcija poziva console.log koja uzima tok izvrsavanja, obavlja svoj posao i onda vraca tok izvrsavanja na red 2
- On tu dolazi do kraja funkcije greet, pa se vraca na mesto gde je bio pozvan, sto je red 5
- Red nakon toga poziva console.log, kada se vrati ta vrednost, program stize do kraja

Posto funkcija, kada vrati vrednost, mora da skoci na mesto koje je poziva, racunar mora da zapamti kontekst u kojem se poziv desio. U ovom slucaju console.log mora da se vrati funkciji greet kada zavrsi. U drugom slucaju vraca se na kraj programa.

Mesto na kom racunar skladisti taj kontekt jeste stek poziva (call stack) Svaki put kada funkcija bude pozvana, tekuci kontekst se kladisti na vrhu steka. Kada se funkcija vrati, ona uklanja kontekst sa vrha steka i koristi ga da nastavi izvrsavaje.

### Opcioni argumenti

Funkciji mozemo proslediti vise argumenata, ali ce ih JavaScript ignorisati.

Definisali smo funkciju square sa samo jednim parametrom. Ali, pozvali smo je sa tri i jezik se ne buni. On ignorise dodatne argumente i izracunava kvadrat prvog.

jsx
function square(x) {
 return x * x;
}
console.log(square(4, true, "jez"));

// ➡️ 16


Ako prosledite previse argumenata, suvisni ce biti zanemareni. 

Ako prosledite premalo argumenata, nedostajucim parametrima bice dodeljena vrednost undefined.

Dobra strana je da se ovo ponasanje moze koristiti kako bi funkcija moigla da bude pozvana s razlicitim brojem argumenata.

Na primer, naredna funkcija minus pokusava da imitira operator - tako sto deluje na bilo koji argument ili na dva argumenta.

jsx
function minus(a, b) {
 if (b === undefined) {
	 return -a;
	}
 else {
	 return a - b;
	}
}

console.log(minuts(10));
// ➡️ -10
console.log(minuts(10, 5));
// ➡️ 5


Ako nakon parametra napisete operator =, a zatim izraz, vrednost tog izraza zamenice argument kada on nije dat.

Na primer, ova verzija funckije power cini njen drugi argument opcionim. Ukoliko ga ne unesete ili prosledite vrednost undefined, on ce imati unapred zadatu vrednost dva i funkcija ce se ponasati kao square.

jsx
const power = function(base, exponent = 2) {
	let result = 1;
	for (let count = 0; count < exponent; count++) {
		result *= base;
	}
	return result;
};

console.log(power(4));
// base ce biti 4, exponent ce biti 2
// ➡️ 16
console.log(power(2, 6));
// base ce biti 2, exponent ce biti 6
// ➡️ 64


### Zatvaranje

Mogucnost da se funkcije tretiraju kao vrednosti, u kombinaciji sa cinjenicom da se lokalne promenljive ponovo prave svaki put kada se funkcija pozove, dovodi do zanimljivog pitanja. 

Sta se desava sa lokalnim promenljivama kada poziv za funkciju koji ih je napravio vise nije aktivan?

Naredni kod pokazuje primer toga. On definise funkciju, wrapValue, koja pravi lokalnu promenljivu. Potom vraca funkciju koja pristupa toj lokalnoj promenljivoj i vraca je.

jsx
function wrapValue(n) {
  let local = n;
  return () => local;
}

let wrap1 = wrapValue(1);
let wrap2 = wrapValue(2);

console.log(wrap1());
console.log(wrap2());


To je dozvoljeno i radi onako kako ocekujete, obema instancama promenljive moze se i dalje pristupiti. Ta situacija je dobar prikaz cinjenice da se lokalne promenljive prave iznova za svaki poziv i da razliciti pozivi ne mogu pregaziti jedni drugima lokalne promenljive.

Ova mogucnost - da se referencira odredjena instanca lokalne promenljive u opsegu koji je obuhvata - naziva se zatvaranje (closure)

jsx
function multiplier(factor) {
	return number => number * factor;
}

let twice = multiplier(2);
console.log(twice(5));
// ➡️ 10


Kada se pozove, telo funkcije vidi okruzenje u kojem je napravljeno, ne i okruzenje u kojem je pozvano.

U primeru, multiplier se poziva i pravi okruzenje u kojem je njen parametar factor vezan za 2. Vrednost funkcije koju ona vraca, a koja je uskladistena u twice, pamti to okruzenje, pa kada bude pozvana, pomnozice svoj argument brojem 2.

Dakle kada smo kreiraki funkciju multiplier (kada smo je dodelili promenljivoj twice), pravi se novo okruzenje i parametar factor je dobio vrednost 2(broj 2 ostaje **zapamćen** u zatvorenom okruženju). Kada pozovemo funkciju, ona vidi okruzenje kada je napravljena pa zato pamti da je dobila bila broj 2 i sada kada je pozvana koristi broj 2 i mnozi ga sa brojem 5.

### Rekurzija

Funkcija koja poziva sama sebe naziva se rekurzivna funkcija (engl. recursive)

Rekurzija omogucava da neke funkcije budu napisane drugacijim stilom.

Uzmite, na primer, ovu alternativnu primenu funkcije power:

jsx
function(base, exponent) {
	if (exponent == 0) {
		return 1;
	} else {
		return base * power(base, exponent - 1);
	}
}

console.log(power(2, 3));
// ➡️ 8


### Razvijanje funkcija

Postoje dve manje vise prirodne situacija u kojima cete funkcije uvoditi u programe.

- Prva je situacija kada primetite da ste slican kod pisali vise puta.
- Druga je situacija kada otkrijete da vam je potrebna neka funkcionalnost koju dosad niste napisali i cini vam se da ona zasluzuje spostvenu funkciju.

### Funkcije i sporedna dejstva

Funkcije se mogu ugrubo razvrstati u one koje se pozivaju zbog njihovih sporednih dejstava i one koje se pozivaju zbog vrednosti koje vracaju. Mada je definitivno moguce i da i jedne i druge imaju i sporedna dejstva i da vracaju vrednost.

Cista funkcija (pure function) posebna je vrsta funkcije koja proizvodi vrednost i ne samo da nema sporedna desjtva, vec se i ne oslanja na sporedna dejstva iz ostatka koda, na primer, ne cita globalne promenljive cija bi se vrednost mogla promeniti. Cista funkcija ima prijatnu osobu da, kada je pozovete sa istim argumentima, uvek daje istu vrednost (i ne radi nista drugo).

### Rezime

Rezervisana rec function, kada se koristi kao izraz, moze da napravi vrednost funkcije.

Kada se koristi kao naredba, ona se moze upotrebiti za deklarisanje promenljive kojoj ce funkcija biti dodeljna kao vrednost. 

Strelicaste funkcije su jos jedan nacin pravljenja funkcija.

jsx
// Definisi f tako da cuva vrednost funkcije
const f = function(a) {
	console.log(a + 2);
};

// Deklasisi g tako da bude funkcija
function g(a, b) {
	return a * b * 3.5;
}

// Manje opsirna vrednost funkcije
let h = a >= a % 3;


Kljucni aspekt u razumevanju funkcija je razumevanje njihove vidljivosti.

Svaki blok pravi nov opseg vidljivosti.

Parametri i promenljive deklarisani u datom opsegu lokalni su i nisu vidljivi spolja.

Promenljive deklarisane pomocu var ponasaju se drugacije, one zavrsavaju u najblizem opsegu funkcije ili u globalnom opsegu.

Odvajanje zadataka koje program obavlja u razlicite funkcije korisna je praksa. Necete se toliko ponavljati, a funkcije mogu pomoci u organizovanju programa grupisuci kod u delove koji obavljaju specificne stvari.
*/

// Vezbe

// Minimum
let min = function (a, b) {
  if (a > b) {
    return b;
  } else {
    return a;
  }
};

console.log(min(2, 4));
console.log(min(4, 2));

// Brojanje slova B
let countBs = function (word) {
  let counter = 0;
  for (let i = 0; i <= word.length - 1; i++) {
    if (word[i] == "B") {
      counter++;
    }
  }
  return counter;
};

console.log(countBs("Babab"));
console.log(countBs("Babaroga"));
console.log(countBs("Cao"));

let countChar = function (word, letter) {
  let counter = 0;
  let wordLowerCase = word.toLowerCase();

  for (let i = 0; i <= wordLowerCase.length - 1; i++) {
    if (wordLowerCase[i] == letter) {
      counter++;
    }
  }
  return counter;
};

console.log(countChar("Babab", "b"));
console.log(countChar("Babaroga", "b"));
console.log(countChar("Ba", "b"));
