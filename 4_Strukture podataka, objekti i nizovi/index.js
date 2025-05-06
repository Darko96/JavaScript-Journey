/*
Brojevi, Bulove vrednosti i znakovni nizovi atomi su od kojih su sacinjene strukture podataka. Medjutim, mnogi tipovi informacija zahtevaju vise od jednog atoma. 

Objekti omogucavaju da grupisemo vrednosti, ukljucujuci i druge objekte, da bismo izgradili slozenije strukture.

### Skupovi podataka

JavaScript nudi specijalan tip podataka za skladistenje sekvenci vrednosti. On se naziva niz (array) i pise se kao lista vrednosti izmedju uglastih zagrada, odvojenih zarezima.

jsx
let listOfNumbers = [2, 3, 5, 7, 11];

console.log(listOfNumbers[2]);
// ➡️ 5
console.log(listOfNumbers[0]);
// ➡️ 2
console.log(listOfNumbers[2 - 1]);
// ➡️ 3


Notacija za dolazenje do elemenata u nizu takodje koristi uglaste zagrade. Par uglastih zagrada neposredno nakon izraza, sa jos jednim izrazom unutar njih, potrazice element u levom izrazu koji odgovara indeksu datom u izrazu u uglastim zagradama.

Prvi indeks niza je nula, a ne jedan.

### Svojstva

U prethodnim poglavljima, videli smo nekoliko izraza sumljivog izgleda, kao sto su myString.length i Math.max. To su izrazi koji pristupaju svojstvu neke vrednosti. 

Dakle pristupima svojstvima length i max koje pripadaju vrednostima myString i Math.

Gotovo sve JavaScriptove vrednosti imaju svojstva. Izuzeci su null i undefined. Ako pokusati da pristupite svojstvu neke od tih ne-vrednosti, dobicete gresku.

jsx
null.length
// ➡️ TypeError: null nas no properties


Dva glavna nacina da pristupte svojstvima u JavaScriptu jesu koriscenje tacke i uglaste zagrade. I value.x i value[x] pristupaju svojstvu koje ima value, ali to ne znaci da je u pitanju isto svojstvo.

Razlika je u tome kako se tumaci x. Kada koristite tacku, rec nakon tacke je doslovno ime svojstva. Kada koristite uglaste zagrade, izraz unutar uglastih zagrada se procenjuje (izracunava) da bi se dobilo ime svojstva. Dok value.x donosi svojstvo vrednosti nazvano x, value[x] pokusava da proceni izraz x i koristi rezultat, pretvoren u znakovni niz, kao ime svojstva.

Tako, ako znate da se svojstvo koje vas zanima zove color, napisacete value.color.

Ukoliko hocete da izdvojite svojstvo nazvano po vrednosti koja se cuva u promenljivoj i, napisacete value[i]. Imena svojstava su znakovni nizovi. To moze biti bilo koji znakovni niz, ali notacija s tackom radi samo sa imenima koja izgledaju kao ispravna imena promenljivih. Znaci, ako hocete da pristupite svojstvu nazvanom 2 ili John Doe, morate koristiti uglaste zagradeL vakue[2] ili value[”John Doe”]

Elementi u bilo kom nizu sladiste se kao svojstva niza, a brojevi su imena svojstava. Posto sa brojevima ne mozete da koristite notaciju sa tackom, a i onako najcesce zelite da koristite promenljivu koja cuva indeks, morate da koristite notaciju sa uglasnim zagradama da biste dosli do njih.

Svojstvo length govori nam koliko elemenata niz sadrzi. To ime svojstva je ispravno ime promenljive i unapred znamo njegovo ime, pa cete, da biste saznali duzinu niza, obicno pisati array.length jer je to lakse nego pisati array[”length”]

### Metode

I objekti znakovnog niza i objekat niza sadrze, pored svojstva length vise svojstava koja cuvaju vrednost funkcije.

jsx
let doh = "Doh";

console.log(typeof doh.toUpperCase);
// ➡️ function
console.log(doh.toUpperCase);
// ➡️ DOH


Svaki znakovni niz ima svojstvo toUpperCase. Kada ga pozovete, dobicete kopiju znakovnog niza u kojoj ce sva slova biti pretvorena u velika slova. Postoji i toLowerCase, koji radi suprotno.

Svojstva koja sadrze funkciju obicno se nazivaju metodama vrednosti kojoj pripadaju, na primer toUpperCase je metoda znakovnog niza.

Ovaj primer prikazuje dve metode koje mozete koristiti da biste radili sa nizovima:

jsx
let sequence = [1, 2, 3]
sequence.push(4);
sequence.push(5);

console.log(sequence);
// ➡️ [1, 2, 3, 4, 5]

console.log(sequence.pop());
// ➡️ 5

console.log(sequence);
// ➡️ [1, 2, 3, 4]


Metoda push dodaje vrednosti na kraj niza, a metoda pop radi suprotno, uklanja poslednju vrednost iz niza i vraca je kao rezultat.

### Objekti

Vrednosti tipa objekat (object) nasumicne su kolekcije svojstava. Jedan nacin da napravite objekat jeste koriscenje viticastih zagrada u izrazu.

jsx
let day1 = {
	squirrel: false,
	events: ["work", "touched tree", "pizza", "running"]
};

console.log(day1.squirrel);
// ➡️ false

console.log(day1.wolf);
// ➡️ undefined

day1.wolf = false
console.log(day1.wolf);
// ➡️ false


Unutar viticastih zagrada nalazi se lista svojstava odvojenih zarezima.

Svako svojstvo ima ime nakon kog stoji dvotacka i vrednost.

Svojstva cija imena nisu ispravna imena promenljivih ili ispravni brojevi, moraju biti postavljena u navodnike.

jsx
let description = {
	work: "Went to work",
	"touched tree": "Touched a tree"
};


To znaci da viticaste zagrade u JavaScriptu imaju dva znacenja. 

- Na pocetku naredbe, one zapocinju blok naredbni.
- Na svakom drugom mestu, one opisuju objekat.

Ocitavanje svojstva koje ne postoji dace vrednost undefined.

Moguce je dodeliti vrednost izrazu svojstva pomocu operatora =

Time cete zameniti vrednost svojstva koja je vec postojala, ili cete napraviti novo svojstvo objekta ako ga nije imao.

Vratimo se nakratko nasem modelu promenljivih s pipcima, promenljive svojstva su slicne. One hvataju vrednosti, ali druge promenljive i svojstva mogli bi drzati te iste vrednosti. Objekte biste mogli posmatrati kao oktopode sa proizvoljnim brojem pipaka, a na svakom od njih istetovirano je ime.

Binarni operator in, kada se primeni na znakovni niz i objekat, govori da li taj objekat ima svojstvo navedenog imena. Razlika izmedju podesavanja svojstva na undefined i brisanja svojstva jeste u tome sto, u prvom slucaju, objekat i dalje ima svojstvo (samo sto ono nema narucito zanimljivu vrednost), dok u drugom slucaju svojstvo vise nije prisutno, pa in vraca vrednost false.

Da biste saznali koje svojstva ima neki objekat, mozete koristiti funkciju Object.keys. Prosledicete joj objekat, a ona ce vratiti niz znakovnih nizova imena svojstava objekta.

jsx
console.log(Object.keys({x: 0. y: 0, z: 2}));
// ➡️ ["x", "y", "z"]


Postoji i funkcija Object assign koja kopira sva svojstva jednog objekta u drugi.

jsx
let objectA = {a: 1, b: 2};
Object.assign(objectA, {b: 3, c: 4});

console.log(objectA)
// ➡️ {a: 1, b: 3, c: 4}


Nizovi su, znaci, samo vrsta objekta specijalizovanog za cuvanje sekvenci stvari. Ako ih ispitate pomocu typeof, dobicete“object”. Mozete ih posmatrati kao dugacke, pljosnate oktopode ciji su svi pipci u urednom redu, obelezeni brojevima.

Dnevnik koji Zak vodi predstavicemo kao niz objekata.

jsx
let journal = [
  {events: ["work", "touched tree", "pizza",
            "running", "television"],
   squirrel: false},
  {events: ["work", "ice cream", "cauliflower",
            "lasagna", "touched tree", "brushed teeth"],
   squirrel: false},
  {events: ["weekend", "cycling", "break", "peanuts",
            "beer"],
   squirrel: true},
  / * itd * /
];


### Izmenjivost

Tipovi vrednosti kao sto su brojevi, stringovi i bulove vrednosti, neizmenljivi su, nemoguce je promeniti vrednost tih tipova. Mozete ih kombinovati i izvoditi nove vrednosti iz njih, ali kada uzmete idredjenu vrednost znakovnog niza, ta vrednost ce uvek ostati ista.

Objekti funkcionisu drugacije. Mozete menjati njihova svojstva, pa vrednost jednog objekta moze imati razlicit sadrzaj u razlicitim trenucima. 

Kada imamo dva broja, 120 i 120, mozemo ih smatrati precizno istim brojem, bilo da se odnose na iste fizicke bitove ili ne. Kod objekata postoji razlika izmedju situacija kada imamo dve reference do istog objekta i situacije kada imamo dva razlicita objekta koji sadrze ista svojstva.

Pogledajte naredni kod:

jsx
let object1 = {value: 10};
let object2 = object1;
let object3 = {value: 10};

console.log(object1 == object2);
// ➡️ true
console.log(object1 == object3);
// ➡️ false

object1.value = 15;
console.log(object2.value);
// ➡️ 15
console.log(object3.value);
// ➡️ 10


Promenljive object1 i object2 drze isti objekat i zbog toga menjanje object1 menja i vrednost object2. Za njih se kaze da imaju isti identitet. Promenljiva object 3 pokazuje drugaciji objekat koji na pocetku sadrzi ista svojstva kao object1 ali zivi odvojenim zivotom.

I promenljive mogu biti izmenjive ili konstante, ali to je odvojeno od nacina na koji se ponasaju njihove vrednosti. Iako se brojace vrednosti ne menjaju, mozete koristiti promenljivu definisanu naredbom let da biste broj koji se menja pratili menjanjem vrednosti na koju promenljiva ukazuje. Slicno tome, iako se povezivanje konstante (const) sa objektom samo po sebi ne moze menjati i konstanta ce uvek pokazivati isti objekat, sadrzaj tog objekta mogao bi se promeniti.

jsx
const score = {visitors: 0, home: 0};
// Ovo je u redu
score.visitors = 1;
// Ovo nije u redu
score = {visitors: 1, home: 1};


Kada poredite objekte pomocu JavaScriptovog operatora ==, on ih poredi po identitetu: dace true samo ako su oba objekta precizno ista vrednost. Poredjenje razlicitih objekata vratice false, cak i ako imaju identicna svojstva.

### Petlje nad nizovima

jsx
for (let i = 0; i < JOURNAL.length; i++) {
  let entry = JOURNAL[i];
  // Uradi nesto sa nizom
}


Ova vrsta petlje je uobicajena u klasicnom JavaScriptu, prolazak kroz nizove, jedan po jedan element, nesto je sto se cesto javlja, a da biste to uradili pokrenucete brojac nad duzinom niza i uzimati svaki element jedan po jedan.

U savremenom JavaScriptu postoji jednostavniji nacin da se napise takva petlja.

jsx
for (let entry of JOURNAL) {
  console.log(${entry.events.length} events.);
}


Kada petlja for izgleda ovako, sa recju of nakon definicije promenljive, ona ce prolaziti kroz elemente vrednosti date nakon of. To funkcionise ne samo na nizovima vec i na znakovnim nizovima i nekim drugim strukturama podataka.

### Dalja nizologija

Metode za dodavanje i uklanjanje stvari na pocetku niza nazivaju se unshift i shift.

jsx
let todoList = [];
function remember(task) {
  todoList.push(task);
}
function getTask() {
  return todoList.shift();
}
function rememberUrgently(task) {
  todoList.unshift(task);
}


Da biste potrazili odredjenu vrednost, na nizovima mozete koristiti metodu indexOf. Ta metoda pretrazuje niz od pocetka do kraja i vraca indeks na kojem se nalazi trazena vrednost, ili -1 ako vrednost nije pronadjena. 

Da biste trazuku od kraja do pocetka, postoji slicna metoda nazvana lastIndexOf.

jsx
console.log([1, 2, 3, 2, 1].indexOf(2));
// ➡️ 1
console.log([1, 2, 3, 2, 1].lastIndexOf(2));
// ➡️ 3


Druga bitna metoda niza jeste slice, koja uzima pocetni i krajnji indeks i vraca niz koji sadrzi samo elemente izmedju njih. Pocetni indeks je ukljucen u dobijeni niz, a krajnji je iskljucen iz dobijenog niza.

Kada kranji indeks nije dat, slice ce uzeti sve elemente nakon pocetnog indeksa. Mozete izostaviti i pocetni indeks da biste kopirali ceo niz.

jsx
console.log([0, 1, 2, 3, 4].slice(2, 4));
// ➡️ [2, 3]
console.log([0, 1, 2, 3, 4].slice(2));
// ➡️ [2, 3, 4]



Metoda concat se moze koristiti za lepljenje nizova kako bi nastao nov niz, slicno onome sto operator + radi sa znakovnim nizovima.

Naredni primer pokazuje metode concat i slice na delu. On uzima niz i indeks i vraca nov niz koji je kopija originalnog niza iz kojeg je uklonjen element na zadatom indeksu.

jsx
function remove(array, index) {
  return array.slice(0, index)
    .concat(array.slice(index + 1));
}
console.log(remove(["a", "b", "c", "d", "e"], 2));
// slice sece niz array i uzima slova a i b
// concat lepi prvi deo koji je isekao slice i dodaje svoj deo, a to su slova d i e
// ➡️ ["a", "b", "d", "e"]


Ako metodi concat prosledite argument koji nije niz promenljivih, ta vrednost ce biti dodata novom nizu promenljivih kao da je to niz sa jednim elementom.

### Znakovni nizovi i njihova svojstva

Iz vrednosti znakovnog niza mozemo ocitati svojstva kao stu length i toUpperCase. Medjutim, ako pokusate da dodate novo svojstvo, ono se nece primiti.

jsx
let kim = "Kim";
kim.age = 88;
console.log(kim.age);
// ➡️ undefined


Vrednosti tipa znakovni niz, broj i bulova vrednost nisu objekti i iako se jezik nece buniti ako pokusate da zadate nova svojstva za njih, on nece zaista sacuvati ta svojstva. Kao sto je ranije pomenuto, takve vrednosti su neizmenjive.

Medjutim, ti tipovi imaju ugradjena svojstva. Svaka vrednost znakovnog niza ima vise metoda. Neke veoma korisne su slice i indexOf, koje podsecaju na istoimene metode nizova.

jsx
console.log("coconuts".slice(4, 7));
// ➡️ nut
console.log("coconut".indexOf("u"));
// ➡️ 5


Razlika je u tome sto indexOf znakovnog niza moze da trazi znakovni niz koji sadrzi vise od jednog znaka, dok odgovarajuca metoda za nizove promenjivih trazi samo jedan element.

jsx
console.log("one two three".indexOf("ee"));
// ➡️ 11


Metoda trim uklanja beline (razmak, nov red, tabulator i slicne znakove) sa pocetka i sa kraja znakovnog niza.

jsx
console.log("  okay \n ".trim());
// ➡️ okay


Funkcija padStart služi za dodavanje znakova na početak stringa kako bi dostigao određenu dužinu. Koristi se kada želimo da formatiramo string tako da ima određeni broj karaktera, popunjavajući početak sa zadatim znakovima. Za argumente uzima zeljenu duzinu i znak za popunjavanje.

jsx
console.log(String(6).padStart(3, "0"));
// ➡️ 006


Znakovni niz mozete podeliti u svakom javljanju drugog znakovnog niza koristeci split i ponovo ga spojiti koristeci jion.

jsx
let sentence = "Secretarybirds specialize in stomping";
let words = sentence.split(" ");
console.log(words);
// ➡️ ["Secretarybirds", "specialize", "in", "stomping"]
console.log(words.join(". "));
// ➡️ Secretarybirds. specialize. in. stomping


Znakovni niz se moze ponoviti metodom repeat koja pravi nov znakovni niz koji sadrzi vise zalepljenih kopija originalnog znakovnog niza.

jsx
console.log("LA".repeat(3));
// ➡️ LALALA


Vec smo videli svojstvo length znakovnog niza. Pristupanje pojedinacnim znakovima u znakovnom nizu izgleda kao pristupanje elementima niza promenljivih.

jsx
let string = "abc";
console.log(string.length);
// ➡️ 3
console.log(string[1]);
// ➡️ b


### Ostali parametri

Ponekad je korisno da funkcija prihvata proizvoljan broj argumenata. Na primer, Math.max izracunava maksimum svih argumenata koje joj prosledite.

Da biste napisali takvu funkciju, postavicete tri tacke pre poslednjeg parametra funkcije, ovako:

jsx
function max(...numbers) {
  let result = -Infinity;
  for (let number of numbers) {
    if (number > result) result = number;
  }
  return result;
}
console.log(max(4, 1, 9, -2));
// ➡️ 9


Kada takva funkcija bude pozvana, ostali parametar je vezan za niz promenljivih koji sadrzi sve naredne argumente. Ukoliko pre njega postoje drugi parametri, njihove vrednosti nisu deo tog niza. Kada je, kao u max, to jedini parametar, on ce sadrzati sve argumente.

Slicnu notaciju sa tri tacke mozete koristiti da biste pozvali funkciju sa nizom argumenata.

jsx
let numbers = [5, 1, 7];
console.log(max(...numbers));
// ➡️ 7


Tako se niz promenljivih “prostire” u pozivu za funkciju, prosledjujuci svoje elemente odvojene argumente. Moguce je ukljuciti takav niz zajedno sa drugim argumentima:

Na primer, max(9, …numbers, 2)

Notacija sa uglastim zagradama za niz omogucava operatoru trostruke tacke da posiri drugi niz u novi niz.

jsx
let words = ["never", "fully"];
console.log(["will", ...words, "understand"]);
// ➡️ ["will", "never", "fully", "understand"]


### Objekat Math

Kao sto smo videli, Math je torba u koju je strpano vise funkcija povezanih sa brojevima, kao sto su Math.max, Math.min, Math.sqrt.

Objekat Math se koristi kao kontejner za grupisanje gomile povezanih funkcionalnosti. Postoji samo jedan objekat Math i on gotovo nikad nije koristan kao vrednost. Umesto toga, on obezbedjuje imenski prostor tako da sve te funkcije i vrednosti ne moraju da budu globalne promenljive.

Zadavanje previse globalnih promenljivih “zagadjuje” imenski prostor. Sto je vise imena zauzeto, to je veca verovatnoca da cete slucajno pregaziti vrednost neke postojece promenljive.

jsx
function randomPointOnCircle(radius) {
  let angle = Math.random() * 2 * Math.PI;
  return {x: radius * Math.cos(angle),
          y: radius * Math.sin(angle)};
}
console.log(randomPointOnCircle(2));
// ➡️ {x: 0.3667, y: 1.966}


Prethodni primer je koristio Math.random. To je funkcija koja vraca nov pseudonasumican broj izmedju nule (ukljucujuci nulu) i jedan (iskljucujuci jedan) svaki put kada je pozovete.

jsx
console.log(Math.random());
// ➡️ 0.36993729369714856
console.log(Math.random());
// ➡️ 0.727367032552138
console.log(Math.random());
// ➡️ 0.40180766698904335


Ukoliko bistmo zeleli ceo nasumican broj umesto decimalnog, mozemo upotrebiti i Math.floor (koja zaokruzuje na najblizi ceo broj) na rezultatu Math.random

jsx
console.log(Math.floor(Math.random() * 10));
// ➡️ 2


Mnozenje nasumicnog broja brojem 10 daje nam veci ili jednak 0 i manji od 10. Posto Math.floor zaokruzuje broj nanize, taj izraz ce proizvesti, s jednakom verovatnocom, bilo koji broj od 0 do 9.

Tu su i funkcije Math.ceil (za zaokruzivanje navise do celog broja), Math.round (do najblizeg celog broja) i Math.abs, koja uzima apsolutnu vrednost broja, sto znaci da negira negativne vrednosti, a pozitivne ostavlja kakve jesu.

### JSON

Posto svojstva samo drze svoju vrednost, umesto da je sadrze, objekti i nizovi promenljivih se skladiste u racunarskoj memoriji kao sekvence bitova sa adresama - mestima u memoriji - za njihov sadrzaj. Znaci niz promenljivih u kojem se nalazi drugi niz priomenljivih sastoji se od (najmanje) jedne memorijske oblasti za unutrasnji niz, i druge za spoljni niz u kojem se nalazi (izmedju ostalog) binarni broj koji predstavlja polozaj unutrasnjeg niza.

Ukoliko zelite da sacuvate podatke u datoteci za kasnije koriscenje, ili za slanje drugom racunaru preko mreze, morate nekako da pretvorite te zapetljane memorijske adrese u opis koji se moze uskladistiti ili poslati. Naravno, mogli biste da posaljete celu racunarsku memoriju zajedno sa adresama vrednosti koje vas zanimaju, ali cini se da to nije bas najbolji pristup.

Ono sto mozemo da uradimo jeste da serijalizujemo podatke. To znaci da se oni konvertuju u ravan opis. Popularan format za serijalizovanje zove se JSON (Dzejson), sto je skracenica za JavaScript Object Notation. On se nasiroko koristi kao format za skladistenje podataka i komunikaciju na vebu, cak i u drugim jezicima, ne samo u JavaScriptu.

JSON izgleda slicno JavaScriptovom nacinu pisanja nizova promenljivih i objekata, uz nekoliko ogranicenja. Sva imena svojstva moraju da budu postavljena u dvostruke navodnike i dozvoljeni su samo jednostavni izrazi sa podacima - nema poziva funkcija, promenljivih niti bilo cega sto ukljucuje izracunavanje. Komentari nisu dozvoljeni u JSON-u.

jsx
{
  "squirrel": false,
  "events": ["work", "touched tree", "pizza", "running"]
}


JavaScript nudi funkciju JSON.stringify i JSON.parse za konvertovanje podataka u ovoj format i iz njega. Prvi uzima JavaScript vrednost i vraca znakovni niz u JSON sifri. Drugi uzima takav niz i konvertuje ga u vrednost koju je sifrovao.

jsx
let string = JSON.stringify({squirrel: false, events: ["weekend"]});

console.log(string);
// ➡️ {"squirrel":false,"events":["weekend"]}
console.log(JSON.parse(string).events);
// ➡️ ["weekend"]


### Rezime

Objekti i nizovi promenljivih (koje su posebna vrsta objekta) nude nacine za grupisanje nekoliko vrednosti u jednu vrednost. Konceptualno, to omogucava da ubacimo gomilu povezanih stvari u torbu i pobegnemo sa tom torbom, umesto da pokusavamo da zadrzimo puno ruke pojedinacnih stvari.

Vecina vrednosti u JavaScriptu imaju svojstva, a izuzeci su null i unedfined.

Svojstvima se pristupa pomocu vrednost.svojstvo ili vrednost[”svojstvo”].

Objekti obicno koriste imena za svoja svojstva i skladiste manje-vise fiksan skup svojstava. Nizovi, sa druge strane, obicno sadrze varirajuce kolicine konceptualno identicnih vrednosti i koriste brojeve (pocevsi od 0) kao imena svojstava.

U nizovima promenljivih postoje neka imenovana svojstva, kao sto je length i vise metoda. Metode su funkcije koje postoje u svojstvima i (obicno) uticu na vrednost cije su svojstvo.

Mozete praviti iteracije nad nizovima promenljivih koristeci posebnu vrstu petlje for 

- for (let element of array).
*/

// Vezbe

// Suma opsega
let range = function (start, end) {
  let array = [];

  for (let number = start; number <= end; number++) {
    array.push(number);
  }
  return array;
};
console.log(range(1, 10));

let sum = function (array) {
  let sum = 0;
  for (let number of array) {
    sum += number;
  }

  return sum;
};
console.log(sum([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]));

let rangev2 = function (start, end, step) {
  let array = [];

  if (step >= 0) {
    for (let number = start; number <= end; number += step) {
      array.push(number);
    }
  } else {
    for (let number = start; number >= end; number -= Math.abs(step)) {
      array.push(number);
    }
  }
  return array;
};
console.log(rangev2(1, 10, 2));
console.log(rangev2(5, 2, -1));

// Obrtanje niza
let reverseArray = function (array) {
  let newReverseArray = array.reverse();
  return newReverseArray;
};
console.log(reverseArray([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]));

let reverseArrayInPlace = function (array) {
  let newReverseArrayInPlace = [];
  while (array.length !== 0) {
    newReverseArrayInPlace.push(array.pop());
  }
  return newReverseArrayInPlace;
};
console.log(reverseArrayInPlace([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]));

// Lista
// Ključna stvar je da petlja ne zamrzava okolinu u kojoj radi, dok prolazi kroz svaki korak,
// ona ima pristup i može menjati vrednosti promenljivih definisanih van nje.

function arrayToList(array) {
  let list = null;

  for (let i = array.length - 1; i >= 0; i--) {
    list = { value: array[i], rest: list };
    // Ova linija ažurira list u svakoj iteraciji, pre nego što sledeći prolaz petlje počne.
    // Dakle, list ne čeka kraj petlje da se promeni, menja se odmah, a petlja koristi novu vrednost pri sledećem koraku.
  }
  return list;
}
console.log(arrayToList([10, 20, 30]));

function listToArray() {}
