# DömösAiTech Penpot plugin — helyi védelmi MVP

Ez a jóváhagyott MVP a Penpot plugin saját műveleteihez ad helyi, determinisztikus kockázat/policy folyamatot, hozzájárulásos auditnaplót és a pluginban megjelenő incidensjelzést.

## Fejlesztés és tesztelés

```sh
npm install
npm test
```

A `build` előbb típusellenőrzi a TypeScriptet, majd a Penpot manifest által használt `plugin.js` fájlt egyetlen bundle-ként állítja elő. A `plugin.html`, `plugin.js`, `manifest.json` és `icon.svg` fájlokat ugyanarról a helyről kell kiszolgálni/megadni a Penpot helyi pluginfejlesztési módjának. A Penpot aktuális útmutatója: [Plugin létrehozása](https://help.penpot.app/plugins/create-a-plugin/).

## Mit csinál

- A plugin saját `get-selection` és `create-rect` művelete bekapcsolt helyi védelemnél a policy-folyamaton megy át; ha az audit nem olvasható/írható, az adott művelet nem fut le.
- A strukturált jelazonosítók lokális, verziózott kockázati szabályokkal kapnak pontszámot. A policy `allow`, `warn`, `challenge` vagy `block` ajánlást ad a specifikáció küszöbei alapján.
- A felhasználó a plugin felületén előre definiált **szimulált** adathalász-, fájl- vagy adatvédelmi jelzést futtathat; ez teszteli a risk/policy/napló útvonalat és helyi figyelmeztetést mutat.
- A napló esemény- és döntésdigestet, kategóriát, pontszámot, műveletet, policy-verziót és hash-láncot tárol; nyers URL, üzenet, dokumentumtartalom vagy személyes azonosító nem kerül bele.
- A külső értesítés/escalation nincs megvalósítva és nincs engedélyezve.

## Tárolás, hozzájárulás és integritás

- A védelem induláskor kikapcsolt. A felhasználó kifejezetten az aktuális Penpot-fájlhoz kapcsolja be.
- A Penpot plugin iframe-ben nem használható böngésző-`localStorage`; az MVP a `penpot.root` pluginadat-tárolóját használja, ezért a napló a jelenlegi tervfájl része. A felületen ez engedélyezés előtt látható.
- A hash-lánc a helyi bejegyzések véletlen vagy egyszerű módosítását észleli, de a Penpot-fájlhoz hozzáférő szerkesztő újraszámíthatja: ez **nem** aláírt, változtathatatlan vagy szerveroldali audit-ledger.
- A napló 1000 bejegyzésnél megáll; a korlát elérésekor új audit nélkül nem futnak a hozzájárulásos, policy-vel védett plugin-műveletek. A helyi védelem kikapcsolható akkor is, ha a napló megtelt.
- A prototípus nem tartalmaz automatikus retention/törlést, exportot vagy helyreállítást hibás lánc esetére. A napló a tervfájlban marad, amíg a fájlban lévő pluginadatot el nem távolítják.

## Kifejezetten nem része ennek az MVP-nek

Nincs böngésző-, fájlrendszer-, chat-, hívás-, identitás-, fizetési vagy eszközszenzor; nincs valós fenyegetésadatbázis, Genesis/GenXid/Carl Compute kapcsolat, aláírt remote policy, backend, automatikus külső értesítés, éles telepítés vagy teljes Penpot-fájlműveletek blokkolása. A tesztjelzések szimuláltak, és nem szabad őket valódi incidensészlelésként kezelni.
