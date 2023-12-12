**Projektimuistio**


Tämän projektin tavoitteena on tehdä vanhasta puhelimesta koiralle jäljitin, jonka avulla voi seurata koiraa metsässä vapaana ulkoiluttaessa, missä koira menee sekä seurata sen liikkumiseen liittyvää dataa. 



**Projektin lähtökohta**

Projekti on osa Oulun Yliopistossa järjestettävää Elektroniikkalaitteiden uudelleenkäytön perusteet -kurssia, jossa tarkoituksena oli keksiä jollekin käytöstä poistetulle elektroniikkalaiteelle uusi käyttötarkoitus. Harrastan ulkoilua koiran kanssa ja olen kaivannut laitetta, jolla koiran voisi paikantaa, mikäli se vapaana ulkoillessa irtoaa näköpiiristä. Lisäksi koen, että tieto koiran kulkemasta matkasta metsälenkin aikana voisi olla hyödyllistä. Tätä tietoa voisi hyödyntää esimerkiksi pelastuskoiratoiminnassa. Pelastuskoiratoiminta on osa Vapaaehtoista pelastuspalvelua ja toimii viranomaisen tukena kadonneen etsimisessä. Koira hakee kadonnutta maa- ja ilmavainulla. Koiran ohjaajan tulee suunnitella annetun alueen etsintä siten, että koko alue tulee tarkastetuksi huomioiden muun muassa koiran yksilöllinen toimintasäde. Koiran liikkumisesta saatava mahdollisimman reaaliaikainen data helpottaisi ja tehostaisi etsintöjä, kun voitaisiin olla varmempia, mitkä alueet ja miten tarkkaan ne on haravoitu. Data olisi myös hyödyllinen väline harjoittelussa, kun se lisäisi tietoa oman koiran liikkeistä ja auttaisi ohjaajaa paremmin suunnittelemaan etsintöjä ja harjoittelua.

Ihmisillä on usein kotonaan käytöstä poistettuja matkapuhelimia, jotka ovat vielä toimintakuntoisia. Tällaisten laitteiden helppo uudelleen hyödynnettävyys olisi erinomaista kestävän kehityksen kannalta. 



**Toiminnot**

Projektin vaatimat toiminnat uudelleen käyttöön otetulta laitteelta
-	koiran sijainnin reaaliaikainen paikallistaminen
-	koiran kulkeman matkan pituus ja reittijälki kartalla
-	laitteen kiinnittäminen koiraan



**Työnkulku**

Aloitin projektin etsimällä käyttöön sopivia vanhoja matkapuhelimia. Valitsin työstettäväksi Nokia Lumia 610, Nokia Lumia 635, Samsung Xcover 271 ja iPhone 8. Aluksi työskentelin nokialaisten parissa. Koska Microsoft on lopettanut Windows-puhelinten tukemisen, erilaiset toiminnot kuten esimerkiksi internetyhteys ovat lakanneet toimimasta puhelimissa. Yritin vaihtaa vanhoihin Lumioihin käyttöjärjestelmäksi Androidin Youtubesta löytämilläni ohjeilla (https://www.youtube.com/watch?v=_OW88UTTDug), vaikkakaan kumpikaan malli ei ollut videon mainitsemalla toimivaksi testattujen mallien listalla. Tässä vaiheessa jouduin luopumaan Lumia 610:stä, koska tietokone ei tunnistanut laitetta oikein (useista uudelleen asennusyrityksistä huolimatta).

Latasin Windows Device Recovery Tool -ohjelman, jonka avulla asensin puhtaan laiteohjelmiston Lumia 635:een, jotta siellä ei olisi mitään, mikä voisi häiritä esilataajan (bootloader) asentamista. Sen jälkeen latasin Windows Phone Internals, jolla oli tarkoitus avata esilataaja (unlock bootloader). Ensin minun oli vaikea löytää koneelta avaamisessa tarvittava FFU-tiedosto, koska en löytänyt videossa annettujen ohjeiden mukaista kansiota. Googlettamalla selvisi, että se oli piilotettu näkyvistä. Löysin kansion ja sain sen näkyväksi, minkä jälkeen FFU-tiedoston lataaminen onnistui (Näytä -> Piilotetut kohteet, tämän jälkeen Kansion ominaisuudet ja merkintä pois kohdasta Piilotettu). Ohjelma kuitenkin herjasi, ettei FFU-tiedosto tukenut OS-käyttöjärjestelmää. Ohjelma neuvoi, että voin käyttää jonkun toisen puhelinmallin FFU-tiedostoa, joka tukee OS-versiota. Jouduin tekemään taas etsintätyötä ja onnistuin löytämään Lumia Firmware -sivuston, josta löysin OS tuetun FFU-tiedoston. Tässä kohtaa videon ohjaus poikkesi lataamastani WP Internals -ohjelmasta, ja minun piti etsiä myös EDE-tiedosto, joka löytyi Lumia Firmwaresta. Nyt pääsin avaamaan esilataajan, mutta tällä kertaa ohjelma herjasi väärästä alustatunnisteesta (profile ffu has wrong platform id for connected phone). Oli pakko jättää työskentely Nokia 635:n kanssa tähän ja siirtyä kokeilemaan onnea Samsungin kanssa.

Samsung Xcover 271 puhelinta kehuttiin eräällä keskustelupalstalla, jossa joku oli käyttänyt puhelinta nimenomaiseen tarkoitukseen koiran paikallistamisessa. Tämä Samsung on ollut ensimmäisiä puhelimia, joihin on tullut internetyhteys. Tuolloin internet toimi ns. WAP-asetuksilla. Wireless Application Protocol on sittemmin poistunut käytöstä. Nettikeskustelussa neuvottiin, että puhelimen wap-selain voisi toimia avoimen wap-välityspalvelimen kautta, tai asentamalla sellainen omalle tietokoneelle ja asettamalla puhelin käyttämään tietokoneen (tai nat-reitittimen) ip-osoitetta wap-välityspalvelimena. Ymmärtääkseni jälkimmäinen vaihtoehto ei hyödyttäisi minun tilanteessani, koska tietokone tai reititin ei ole siellä, missä jäljitintä on tarkoitus käyttää. En saanut myöskään avoimia wap-asetuksia toimimaan. Todennäköisesti jatkossa ongelmana olisi ollut myös se, ettei WAP-selaimet avaa nykyaikaisia nettisivuja kovin hyvin, joten oletettavasti karttasovellusten käyttäminen olisi ollut mahdotonta.
Loppujen lopuksi päädyin käyttämään projektissa vanhaa iPhone 8, joka oli vielä puhelimenakin toimiva, mutta olen poistanut sen käytöstä, koska näyttö on halkeillut ja akun kesto huomattavasti lyhentynyt.

Laitteen kiinnittämiseksi koiraan lainasin siskoltani mummoltamme perittyä ompelukonetta. Ompelin vanhoista trikoohousuista vetoketjullisen pussukan, jonka kiinnitin ompelemalla koiran vanhoihin huomioliiveihin.

![IMG_2224](https://github.com/nibblesist/tracker/assets/152255971/00c34e98-225a-4c54-8c46-370f0a5f3e08)


**Saatavilla olevat applikaatiot ja niiden vertailu**

Tutkin erilaisia sijaintia jakavia ja liikkumisdataa tallentavia sovelluksia. Jälkimmäiseen tarkoitukseen löytyy runsaasti sovelluksia, jotka kehitetty lähinnä erilaisten urheilusuoritusten seurantaan, kuten esimerkiksi Strava, Sports Tracker ja HeiaHeia. Suurimmassa osassa sovelluksia voit jakaa liikkumisdatan muille käyttäjille, mutta reaaliaikaista sijaintia sovelluksissa ei pysty jakamaan. Google mapsissa sijainnin jakaminen onnistuu, mutta se ei tallenna liikkumisdataa. Sen sijaan löysin retkeilyyn kehitetyn sovelluksen Outdooractive, jolla liikkumisdatan tallentamisen lisäksi voi jakaa (maksullisessa versiossa) myös reaaliaikaisen sijainnin. Sijaintitieto päivittyy minuutin välein ja piirtää (oletetusti) kuljettua reittiä (tästä huomioita jäljempänä). Outdooractivessa oli mahdollisuus 14 päivän ilmaiseen kokeilujaksoon, jonka jälkeen hinta on 29,90€/vuosi. Koska käytössäni oli oma vanha iPhone, johon olin kirjautunut samalla Apple ID:lla kuin tällä hetkellä käytössäni olevalla puhelimella pystyin käyttämään sovellusta samalla tilauksella molemmissa laitteissa. Koiralla olevassa laitteessa oli kuitenkin eri tili kuin omassani, jotta ohjelma tunnisti ne erillisiksi ja seuraaminen onnistui.



**Jäljittimen demoaminen ja korjaukset**

Tein testiharjoituksen jäljittimellä 9.12. Rovaniemellä. Tavoitteena oli tehdä kadonneen etsintäharjoitus, ja saada tilanteesta sekä ohjaajan että koiran kulkeman reittijälki kartalle. Etsinnässä käytetty alue oli minulle entuudestaan hyvin tuttu ja etsittävä henkilö koiralle tuttu. Koira lähtee yleensä voimakkaasti tutun henkilön hajujäljen perään, kun taas vierasta henkilöä etsittäessä koira voi olla epävarmempi ja irrota ohjaajalta heikommin. Tavoitteenani oli kulkea alueen poikki kohti suunnilleen tiedossa olevaa piilopaikkaa, jolloin koira tekee ohjaajan ympärillä hakuja ilmavainulla. Kartan avulla oli tarkoitus selvittää, kuinka hyvin kyseinen alue tuli tarkastettua ja millä säteellä koira ohjaajasta työskenteli. Alue oli osittain metsää ja osittain hakkuuaukeaa. Etsintäpäivänä lämpötila oli noin -11 ja lunta oli metsäisellä alueella 20-40 senttimetriä, hakkuuaukealla paikoitellen reilusti yli puoli metriä.

![IMG_2521](https://github.com/nibblesist/tracker/assets/152255971/d5ca9f7f-6c96-4192-bbd5-614d6cfec6cb)
![IMG_4621](https://github.com/nibblesist/tracker/assets/152255971/ef815ba9-25c1-47d4-8504-5b9b4e3e217a)

Yllä olevat kuvat näyttävät kuljetut reitit. Ensimmäisessä kuvassa punaisella merkitty reitti on ohjaajan kulkema ja jälkimmäinen ruskealla merkitty reitti koiran kulkema. Karttaan on merkitty punaisella rastilla etsittävän henkilön piilopaikka. Kuvien yläosassa oleva data näyttää, että koiran kulkema matka on kaksi kertaa pidempi kuin ohjaajan matka. Lopputulos ei vastannut aivan haluttua, koska lunta oli sekä ohjaajalle että koiralle liikaa. Keltaisella karttaan merkitty alue oli hakkuuaukeaa, jota pitkin ei käytännössä voinut kulkea. Alueella piti liikkua polkuja pitkin, mikä selittää, miksi koira on liikkunut lähes identtisesti saman reitin kuin ohjaaja. Reitin alussa vähemmän lumisella metsäalueella kartassa näkyy, kuinka koira on tehnyt muutamia hakuja sivuun ohjaajan kulkemasta reitistä. Helpommassa maastossa nämä hakuympyrät olisivat isompia ja haut pidempiä.

Toisen tekemäni demon tarkoitus oli näyttää, kuinka sijainnin jakaminen toimii Outdooractive -sovelluksessa. Projektista löytyy näytöltä tallennettu video (Jaettusijainti.mov), joka on editorilla nopeutettu katsomiskokemuksen parantamiseksi. Todellisuudessa sijainti päivittyi minuutin välein, kuten edellä jo mainitsin. Havainnollistamisen helpottamiseksi järjestin tilanteen, jossa koira etsisi jälleen tuttua henkilöä ja oletettavasti irtoaisi ohjaajasta paremmin. Tässä kohtaa ongelmaksi muodostui pakkanen, joka tuntui jo vaikuttavan koiraan edellisessä etsintätilanteessa. Koira on koulutettu etsintään ja yleensä lähtee helposti käyttämään nenäänsä. Nyt koira ei tutuista käskyistä huolimatta lähtenyt tekemään etsintää ilmavainuisesti, mikä näkyi esimerkiksi aikaisemmassa etsinnässä niin, että koira reagoi hajuun paljon myöhemmin kuin tavallisesti ja löysi ihmisen lopulta vasta hajujäljen perusteella. Tässä videolla esitetyssä demossa koira pysytteli ohjaajan läheisyydessä ja teki vain lyhyitä irtiottoja. Videolla koira paikantuu lähelle ohjaajan sijaintia ja koiran oletetusti kulkemareitti piirtyy ohjaajan kulkemaan reittiin. Todellisuudessa koira teki jonkin verran hakuja ohjaajan edelle, mutta palasi usein takaisin alle minuutissa, jolloin minuutin välein päivittyvä seuranta ei ehtinyt mukaan.

**Kuvia testialueelta**

Alla on muutamia kuvia testialueelta edellisiltä päiviltä, jolloin lunta oli vähemmän.

![IMG_2364](https://github.com/nibblesist/tracker/assets/152255971/a19d389b-a1b8-4535-8101-5c378ffe6476)
![IMG_2366](https://github.com/nibblesist/tracker/assets/152255971/3aa2fe16-a7f2-41b6-bbc0-8ca8eb19da3f)
![IMG_2365](https://github.com/nibblesist/tracker/assets/152255971/a500a137-f515-4427-845b-429b673df729)
![IMG_2299](https://github.com/nibblesist/tracker/assets/152255971/9d0477a4-a6a9-4328-b9c1-aa0a63336ffe)
![IMG_2302](https://github.com/nibblesist/tracker/assets/152255971/732766ab-6501-4355-9cf2-28e30aef54fa)

**Jatkokehittely**

Jouduin lopulta käyttämään projektissa puhelinta, joka toimi hyvin myös alkuperäiseksi tarkoitetussa käytössä. Kestävän kehityksen kannalta olisi kuitenkin parempi hyödyntää laitteita, jotka olisivat menettäneet käyttötarkoituksensa. Näitä laitteita löytyy huomattavasti enemmän ihmisten kodeista, ja tällaisten laitteiden hyödyntäminen eli mahdollisimman lyhyt kierto kierrätyksessä olisi tavoiteltavaa. Jatkokehittelynä voisi mahdollisesti tehdä sovelluksen, jossa samalle tilille voisi luoda useamman laiteen ja mahdollisesti jopa kytkeä koirassa olevan laitteen seurannan tai jäljen tallennuksen päälle omasta päälaitteesta.
