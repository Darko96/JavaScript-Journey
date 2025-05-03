/*
Unutar racunarskoj sveta sustinski postoje samo podaci.

Svi ti podaci su uskladisteni kao dugacke sekvence bitova i zbog toga su, u osnovi, slicni.

Bitovi(bits) su bilo sta sto ima dve vrednosti, obicno opisane kao nule i jedinice. U racunaru oni poprimaju oblik kao sto je visok i nizak elektricni naboj, jak ili slab signal ili sjajna ili zamucena tacka na povrsini CD-a. Bilo koji komad informacije moze se svesti na sekvencu nula i jedinica i time predstaviti bitovima.

Broj 13 mozemo izraziti u bitovima. To funkcionise isto kao decimalni broj, ali umesto deset rezlicitih cifara(0, 1, 2, 3, 4, 5, 6, 7, 8, 9), imate samo dve (0, 1) a tezina svake se povecava dva puta, zdesna ulevo. Evo bitova koji cine broj 13, sa tezinom cifara prikazanom ispod njih.

| 0   | 0   | 0   | 0   | 1   | 1   | 0   | 1   |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 128 | 64  | 32  | 16  | 8   | 4   | 2   | 1   |

Dakle to je binarni broj 00001101. Vrednosti cifara koje nisu nule su 8, 4 i 1. I u zbiru daju 13.

## Vrednosti

Zamislite more bitova ili citav okean. Danasnji racunar sadrzi 30 milijardi bitova u svojoj radnoj verziji. Hard diskovi obicno ima nekoliko redova velicine vise. 

Da bismo mogli da radimo sa tolikom kolicinom bitova, a da se ne izgubimo, moramo ih podeliti u komade koji predstavljaju delove informacija. U okruzenju JavaScripta, ti komadi se nazivaju vrednosti (values). Iako su sve vrednosti sacinjene od bitova, one igraju razlicite uloge. Svaka vrednost ima tip koji odredjuje njenu ulogu. Neke vrednosti su brojevi, neke su tekst, neke su funkcije itd.

Svaka vrednost mora negde da bude uskladistena i ako zelite da korisite ogromnu kolicinu vrednosti istovremeno, moglo bi vam ponestati memorije. Srecom, to je problem samo ako vam sve one trebaju istovremeno.

Dakle vrednosti su skup bitova koji zajedno predstavljaju komad neke informacije.

## Brojevi

Vrednosti tipa broj (number) jesu brojcane vrednosti.

U JavaScript programu, one se zapisuju ovako: 

jsx
13 


Upotrebite to u programu i u memoriji racunara ce nastati obrazac bitova za broj 13

JavaScript koristi fiksan broj bitova, 64, za skladistenje jedne brojcane vrednosti.

jsx
// regularni broj
13

// decimalni broj
9.81


Za veoma velike ili veoma male brojeve, mozete koristiti naucnu notaciju tako sto cete dodati e (za eksponent), i nakon toga napisati eksponent broja.

jsx
2.998e8

// To je
2998 x 108 = 299.800.000


Izracunavanje sa celim brojevima (integers) manjim od gorepomenutih 9 bilijardi, garantovano ce uvek biti precizna. Nazalost, izracunavanja sa decimalnim brojevima obicno nisu.

### Aritmetika

Glavna stvar koju cete raditi sa brojevima jeste aritmetika.

Aritmeticke operacije kao sto je sabiranje ili mnozenje uzimaju dve brojcane vrednosti i od njih porizvode nov broj.

Evo kako to izgleda u JavaScriptu:

jsx
100 + 4 * 11


Znaci + - * / %  su operatori. Prvi predstavlja sabiranje, a drugi mnozenje. Postavljanje operatora izmedju dve vrednosti primenice tu operaciju na vrednosti i proizvesti novu vrednost.

Za oduzimanje se koristi operator -, a deljenje se moze obaviti operatorom /.

Znak % se koristi za predstavljanje ostaka. x % y jeste ostatak deljenja broja x brojem y. Ovaj operator cesto se naziva i modulo.

### Posebni brojevi

U JavaScriptu postoje tri posebne vrednosti koje se smatraju brojevima, ali se ne ponasaju kao obicni brojevi.

Prve dve su Infinity i -Infinity i one predstavljaju pozitivnu i negativnu beskonacnost.

NaN predstavlja “nije broj” iako tip te vrednosti jeste broj. taj rezultat cete dobiti, na primer, kada pokusate da izracunate 0 / 0, Infinity - Infinity, ili bilo koju od vise numerickih operacija koje ne daju smislen rezultat.

jsx
// pozitivna beskonacnost
Infinity

// negativna beskonacnost
-Infinity

// nije broj - iako tip te vrednosti jeste broj
NaN

console.log(0 / 0); ➡️ NaN
// NaN dobijamo kada vrsimo matematicke operacije koje ne daju smislen rezultat.


### Znakovni nizovi

Naredni osnovni tip podataka jeste Znakovni niz(string). Znakovni nizovi se koriste za predstavljanje teksta. Oni se pisu postavljanjem njihovog sadrzaja izmedju navonika.

jsx
"Down on the sea"


Kad god se u tekstu nalazi obrnuta kosa crta ( / ), ona oznacava da znak nakon nje ima posebno znacenje. to je izlazna sekvenca za znak.

Kada se nakon obrnute kose crte pojavi znak n, on se tumaci kao nov red. Slicno tome, t nakon obrnute kose crte predstavlja znak za tabulator.

Znak za novi red(newline) koji se dobija kada pritisnete Enter, moze se dobiti bez koriscenja izlazne skevence za znakovne samo ako znakovni niz obuhvatite obrnutim poludavonicima(  ).

jsx
\" - ne zavrsava string nego ce navodnik biti deo string-a
\n - predstavlja novi red
\t - predstavlja novi tab (prazno mesto)
\\ - predstavlja jednu kosu crtu unutar string-a


I znakovni nizovi moraju da budu oblikovani kao nizovi bitova da bi mogli da postoje u racunaru.

Nacin na koji JavaScript to radi zasnovan je na standardu Unicode. Taj standard dodeljuje broj svakom znaku koji bi vam ikada mogao zatrebati.

Ukoliko imamo broj za svaki znak, znakovni niz moze biti opisan kao sekvenca bitova.

Znakovni nizovi se ne mogu deliti, mnoziti ili oduzimati, ali operator + moze se koristiti na njima.On ne samo da ih sabira, vec ih nadovezuje(concatenate) lepi dva znakovna niza jedan za drugi. Naredni red ce proizvesti znakovni niz “concatenate”

jsx
// Znak plus se moze koristiti za nadovezivanje(concatenate) string-ova
"con" + "cat" + "e" + "nate"


Postoji vise funkcija (metoda) koje se mogu koristiti da bi se na vrednostima tipa znakovni niz izvele druge operacije.

Znakovni nizovi napisani sa polunavodnicima ili navodnicima ponasaju se isto, razlika je samo u tome koji tip navonika zelite da upotrebite unutar samog znakovnog niza.

Znakovni nizovi postavljeni u obrnute polunavodnike obicno se nazivaju sablonski literali (template literals) i mogu da urade jos neke trikove. Osim sto mogu da se prostiru u vise redova, u njih mozete ugraditi druge tipove vrednosti.

jsx
pola od 100 je ${100 / 2}


Kada u sablonskom literalu nesto napisete unutar ${ }, rezultat toga ce biti izracunat, pretvoren u znakovni niz i dodat na to mesto. Gornji primer daje pola od 100 je 50.

### Unarni operatori

Nisu svi operatori simboli. Neki se pisu kao reci. Jedan primer je operator typeof, koji vraca tip vrednosti koju ste mu prosledili.

jsx
console.log(typeof 4.5) // ➡️ number


Operatori koji koriste dve vrednosti nazivaju se binarni operatori.

Operatori koji uzimaju jednu vrednost nazivaju se unarni operatori.

Operator minus moze se koristiti i kao binarni i kao unarni operator.

jsx
console.log(- (10-2))
// ➡️ -8


### Bulove vrednosti

Cesto je korisno imati tip vrednosti koji pravi razliku izmedju dve mogucnosti, kao sto su da i ne ili ukljuceni i iskljuceno. Za to namenu, JavaScript ima tip Boolean.

Boolean (Bulove, logicke vrednosti) ima samo dve vrednosti, true i false.

jsx
console.log(3 > 2) // ➡️ true


Poredjenje

Evo jednog nacina da se proizvede Bulova vrednost:

jsx
console.log(3 > 2)
// ➡️ true

console.log(3 < 2)
// ➡️ false


Znakovi > i < su tradicionalni simboli za vece od i manje od. Oni su binarni operatori. Njihova primena za rezultat ima Bulovu vrednost koja oznacava da li je iraz tacan u datom slucaju.

Drugi slicni znakovi su >= (vece ili jednako), <= (manje ili jednako), == (jednako), != (razlicito)

Postoji samo jedan vrednost u JavaScript koja nije jednaka sama sebi, a to je NaN.

jsx
console.log(NaN == NaN)
// ➡️ false


NaN bi trebalo da oznacava da nema rezulatata u racunanju koji ima smisla.

### Logicki operatori

Postoje neke operacije koje se mogu primeniti na same Bulove vrednosti.

JavaScript podrzava tri logicka operatora: i ili i ne

Oni se mogu koristiti za rasudjivanje o Bulovim vrednostima.

Operator && predstavlja logicni i. To je binarni operator i njegov rezultat je true samo ako su obe date vrednosti true.

Operator || oznacava logicko ili. Ono daje rezultat true ako je bilo koja dodeljena vrednost true.

Ne operator je unarni operator koji obrce vrednost koja mu je data.

jsx
!ture // ➡️ false


Pri mesanju Bulovih operatora sa aritmetickim i drugim operatorima, nije uvek ocigledno kada su vam potrebne zagrade. U praksi je obicno dovoljno da znate da od operatora koje ste do sad videli, || ima najnizi prioritet, sledi && pa operatori poredjenja (>, <, ==) i onda ostali. Taj redosled je izabran tako da vam je, u tipicnim izrazima kao sto je naredni, potrebno sto je moguce manje zagrada:

jsx
1 + 1 = 2 && 10 * 10 > 50


Ternarni operator radi sa tri vrednosti. Naziva se uslovni operator jer je jedini takav operator u jeziku. Vrednost levo od upitnika bira koja ce od druge dve vrednosti biti rezultat. Kada je vrednost levo od upitnika true, ona za rezultat bira srednju vrednost, a kada je false, rezultat je desna vrednost.

jsx
console.log(true ? 1 : 2) 
// ➡️ 1

console.log(false? 1 : 2) 
// ➡️ 2


### Prazne vrednosti

Postoje dve posebne vrednosti: null i undefined , koje se koriste za oznacavanje nedostatka smislene vrednosti. One same za sebe jesu vrednosti, ali ne sadrze nikakve informacije.

Mnoge operacije u jeziku koje ne proizvode smislenu vrednost za rezultat daju undefined prosto zato sto moraju da daju neku vrednost.

Razlika u znacenju izmedju undefined i null je slucajnost JavaScriptovog dizajna, i u vecini slucajeva nije bitna. U situacijama kada treba da se bavite tim vrednostima, preporucujem da ih tretirate kao vrednosti koje uglavnom mogu zamenjivati jedna drugu.

### Automatska konverzija tipa

Kada je operator primenjen na pogresan tip vrednosti, JavaScript ce tiho poretvoriti tu vrednost u tip koji mu treba, koristeci skup pravila koja cesto nisu ono sto biste ocekivali. To se naziva konverzija tipa (coercion. Vrednost null u prvom izrazu postaje 0, a “5” u drugom izrazu postaje 5 (umesto znakovnog niza postaje broj). U trecem izrazu + pokusava da nadoveze znakovne nizove pre nego da sabere brojeve, pa je 1 pretvoreno u “1” (umesto broja postaje znakovni niz).

jsx
console.log(8 * null) // ➡️ 0

console.log("5" - 1) // ➡️ 4

console.log("5" + 1) // ➡️ 51

// Kada se u broj pretvara nesto sto ne odgovaraja broju na ocigledan nacin 
// ("five" ili undefined), dobicete vrednost NaN.
console.log("five" * 2) // ➡️ NaN

console.log(false == 0) // ➡️ true

// Kada poredite vrednosti istog tipa koristeci ==, rezultat je lako predvideti: 
// treba da dobijete true ako su obe vrednosti iste, osim u slucaju NaN.
// Medjutim, kada su null i undefined javljaju na bilo kojoj strani operatora, rezultat 
//ce biti true samo ako je i na drugoj strani operatora vrednost null ili undefined
console.log(null == undefined)➡️ true


Za null i undefined takvo ponasanje je cesto korisno. Kada hocete da testirate da li je neka vrednost prava vrednost, a ne null ili undefined, mozete da je uporedite sa null koristeci operator == ili !=

Kada ne zelite da dodje do automatske konverzije tipa, postoje dva dodatna operatora === i !==

### Skraceno izracunavanje logickih operatora

|| vraca vrednost koja mu stoji na levoj strani kada se ona moze pretvoriti u true, a inace vraca vrednost na desnoj strani.

jsx
console.log(null || "user") // ➡️ user

console.log("Agnes" || "user") // ➡️ Agnes


Tu funkcionalnost mozemo koristiti kao nacin da se vratimo na unapred zadatu vrednost. Ako imate vrednost koja bi mogla biti prazna, mozete nakon nje postaviti || sa zamenskom vrednoscu. Ukoliko pocetna vrednost moze biti konvertovana u false, umesto nje cete dobiti zamensku vrednost.

&& kada je vrednost na njegovoj levoj strani nesto sto se pretvara u false, on vraca tu vrednost, a inace vraca vrednost koja mu stoji desno.

jsx
console.log("" && "Milena") // ➡️ ""

console.log("Milena" && "Darko") // ➡️ Darko


Drugo bitno svojstvo ova dva operatora jeste da se deo koji ima stoji desno procenjuje samo kada je to neophodno.

jsx
// Ma sta da je X rezultat ce biti true
console.log(true || "X") // ➡️ true


To se naziva skraceno izracunavanje (short-circuit evaluation)

### Rezime

4 tipa JavaScriptovih vrednosti: 

- brojevi
- znakovni nizovi
- bulove vrednosti
- nedefinisane vrednosti

Binarni operatori su za aritmeticke opracije (+ - * /)

Operatore za nadovezivanje znakovnih nizova (+)

Poredjenje (== != === !== < > <= >=)

Logicke operatore (&& ||)

Unarni operatori (- ! typeof)

Ternarni operator (?:)
*/
