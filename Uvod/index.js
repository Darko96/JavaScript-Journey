/*
Programiranje je cin konstruisanja programa, skupa preciznih instrukcija koje govore racunaru sta da radi.

Vecina programiranja obavlja se uz pomoc programskih jezika.

Program je vise od programa. To je deo teksta koji je napisao programer, to je upravljajuca sila koja tera racunar da radi ono sto radi, to su podaci u memoriji racunara, ali upravljaju akcijama koje se izvode na toj istoj memoriji.

Program moze genijalno da kombinuje ogromne brojeve prostih akcija da bi uradio veoma slozene stvari.

Programski jezik je vestacki konstruisan jezik koji se koristi za zadavanje instrukcija racunarima.

- Kao i govorni jeziki, racunarski jezici omogucavaju da se reci i fraze kombinuju na nove nacine, zahvaljujuci cemu je moguce izraziti nove koncepte.

JavaScript je ugradjen u svaki pretrazivac i stoga je dostupan gotovo na svakom uredjaju.

### Zasto je jezik bitan?

U vreme nastanka racunara nisu postojali programski jezici. Programi su izgledali otprilike ovako:

00110001 00000000 00000000

00110001 00000001 00000001

00110011  00000011 00000010

Ovo je skracena verzija programa za sabiranje brojeva od 1 do 10 i prikazivanje rezultata.

Da bi se programirali rani racunari, bilo je neophodno postaviti velike nizove prekidaca u odgovarajuci polozaj ili busiti rupe u kartonskim trakama i ubacivati ih u racunar.

Svaki red prethodnog programa sadrzi jednu instrukciju. Na srpskom bi se to moiglo napisati ovako:

1. Uskladisti broj 0 na memorijsko mesto 0
2. Uskladisti broj 1 na memorijsko mesto 1
3. Uskladisti vrednost memorijskog mesta 1 na memorijsko mesto 2
4. Oduzmi broj 11 od vrednosti na memorijskom mestu 2

Iako je ovo vec citljivije od buckurisa bitova, jos uvek je krajnje nejasno.

Koriscenje imena umesto brojeva za instrukcije i memorijska mesta pomaze.

1. Podesu “total” na 0
2. Podesi “count” na 1
3. Podesi “compare” na “count”
4. Oduzmi 11 od “compare”

Evo istog programa u JavaScriptu.

let total = 0, count = 1
while (count <= 10) {
	total += count;
	count += 1;
}
console.log(total);
// ➡️ 55

Isti program sa zgodnim operacijama range i sum”

console.log(sum(range(1, 10)));
// ➡️ 55

Dobar programski jezik pomaze programeru omogucavajuci mu da na visem nivou govori o akcijama koje racunar treba da izvrsi. To pomaze da se izostave detalji, obezbedjuje zgodne gradivne blokove (kao sto su while i console.log), dozvoljava vam da definisete sopstvene gradivne blokove (kao sto su sum i range), i cini lakim uklapanje tih blokova.

### Sta je JavaScript?

JavaScript je predstavljen 1995. kao nacin da se programi dodaju web stanam u citacu Netscape Navigator. Taj jezik je u medjuvremenu prihvacen u svim glavnim grafickim citacima veba. On je ucinio mogucim moderne veb aplikacije - aplikacije s kojima mozete imati direktne interakcije, ne morajuci ponovo da ucitavate stranu za svaku akciju.

Veb pretrazivaci nisu jedine platforme na kojima se koristi JavaScript. Neke baze podataka, kao sto su MongoDb, koriste JavaScript kao svoj jezik za izradu skriptova i upita. 

Nekoliko platformi za desktop i serversko programiranje, od kojih je najvazniji projekat Node.js, nude okruzenje za programiranje na JavaScriptu van veb pretrazivaca.

Kod je tekst koji cini programe.
*/
