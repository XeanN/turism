// Mapeo slug <-> id numérico del backend (cloud-pe.com no tiene campo slug
// ni idioma). Si se agrega/renombra un tour en el backend, hay que agregar
// su entrada aquí para que tenga slug amigable y meta tags propios; si no
// aparece, TourDetails cae de todos modos al id numérico como respaldo.
export const toursSeo = [
  {
    id: "1",
    slug: "fullday-paracas-and-huacachina",
    title_en: "FullDay Paracas and Huacachina - Adventure and Nature",
    description_en:
      "Explore Paracas and Ica in one day. Ballestas Islands, Huacachina oasis, vineyards, history and dune buggy adrenaline from Lima.",
    title_es: "FullDay Paracas y Huacachina - Aventura y Naturaleza",
    description_es:
      "Explora Paracas e Ica en un día. Islas Ballestas, oasis de Huacachina, viñedos, historia y adrenalina en carros areneros desde Lima.",
  },
  {
    id: "2",
    slug: "islas-ballestas",
    title_en: "Ballestas Islands - Peruvian Marine Wildlife",
    description_en:
      "Sail to the Ballestas Islands to see sea lions, penguins and exotic birds in their natural habitat.",
    title_es: "Islas Ballestas - Fauna Marina Peruana",
    description_es:
      "Navega a las Islas Ballestas para ver lobos marinos, pingüinos y aves exóticas en su hábitat natural.",
  },
  {
    id: "3",
    slug: "private-tour-paracas",
    title_en: "Private Tour in Paracas - Personalized Experience",
    description_en:
      "Live a unique and exclusive experience with our private tours in Paracas, Ica or Nazca.",
    title_es: "Tour Privado en Paracas - Experiencia Personalizada",
    description_es:
      "Vive una experiencia única y exclusiva con nuestros tours privados en Paracas, Ica o Nazca.",
  },
  {
    id: "4",
    slug: "yacht-charter-paracas",
    title_en: "Yacht Charter in Paracas - Luxury and Freedom",
    description_en:
      "Charter a private yacht and sail the waters of Paracas in style, comfort and total privacy.",
    title_es: "Alquiler de Yates en Paracas - Lujo y Libertad",
    description_es:
      "Alquila un yate privado y navega por las aguas de Paracas con estilo, confort y privacidad total.",
  },
  {
    id: "5",
    slug: "special-services-paracas",
    title_en: "Special Services in Paracas - Custom Events and Services",
    description_en:
      "We offer corporate tours, filming, weddings, and unique personalized experiences at sea or in the desert.",
    title_es: "Servicios Especiales en Paracas - Eventos y Servicios a Medida",
    description_es:
      "Ofrecemos tours corporativos, filmaciones, bodas y experiencias únicas personalizadas en el mar o desierto.",
  },
  {
    id: "6",
    slug: "ballestas-island-and-nature-reserve",
    title_en: "Ballestas Islands and Nature Reserve All-Inclusive - Paracas",
    description_en:
      "All-inclusive tour: Ballestas Islands and Paracas National Reserve in one outing, with transport and guide.",
    title_es: "Islas Ballestas y Reserva Nacional All-Inclusive - Paracas",
    description_es:
      "Tour todo incluido: Islas Ballestas y Reserva Nacional de Paracas en una sola salida, con transporte y guía.",
  },
  {
    id: "7",
    slug: "tpp-paracas-all-inclusive-tour",
    title_en: "All-Inclusive Tour from TPP Paracas - Islands and Reserve",
    description_en:
      "Depart from the Paracas Port Terminal and discover the Ballestas Islands and the National Reserve in a single tour.",
    title_es: "Tour All-Inclusive desde TPP Paracas - Islas y Reserva",
    description_es:
      "Sal desde el Terminal Portuario de Paracas y conoce las Islas Ballestas y la Reserva Nacional en un solo tour.",
  },
  {
    id: "8",
    slug: "chan-chan-trujillo-salaverry",
    title_en: "Chan Chan and Trujillo from Salaverry Cruise Terminal",
    description_en:
      "Cultural excursion to Chan Chan and Trujillo for cruise passengers arriving at the Salaverry Terminal.",
    title_es: "Chan Chan y Trujillo desde Terminal de Cruceros Salaverry",
    description_es:
      "Excursión cultural a Chan Chan y Trujillo para pasajeros de cruceros que llegan al Terminal de Salaverry.",
  },
  {
    id: "9",
    slug: "paracas-national-reserve-private-tour",
    title_en: "Paracas National Reserve - Private Tour",
    description_en:
      "Discover the marine biodiversity and unique landscapes of the Peruvian coastal desert on a private tour of the reserve.",
    title_es: "Reserva Nacional de Paracas - Tour Privado",
    description_es:
      "Conoce la biodiversidad marina y los paisajes únicos del desierto costero peruano en un tour privado por la reserva.",
  },
  {
    id: "26",
    slug: "nazca-lines",
    title_en: "Nazca Lines - Mysteries of the Desert",
    description_en:
      "Fly over the enigmatic Nazca Lines and discover one of the greatest mysteries of ancient Peru.",
    title_es: "Líneas de Nazca - Misterios del Desierto",
    description_es:
      "Vuela sobre las enigmáticas Líneas de Nazca y descubre uno de los mayores misterios de la antigüedad peruana.",
  },
  {
    id: "27",
    slug: "mini-buggies-paracas",
    title_en: "Mini Buggies in Paracas - Dune Adventure",
    description_en:
      "Enjoy the thrill of sandboarding and a buggy ride through the dunes of Peru's southern coast.",
    title_es: "Mini Buggies en Paracas - Aventura en las Dunas",
    description_es:
      "Disfruta de la emoción del sandboarding y un recorrido en buggy por las dunas de la costa sur del Perú.",
  },
];

export const findTourSeoBySlug = (slug) =>
  toursSeo.find((t) => t.slug === slug);

export const findTourSeoById = (id) =>
  toursSeo.find((t) => t.id === String(id));

export const getTourSeoText = (entry, lang) =>
  lang === "es"
    ? { title: entry.title_es, description: entry.description_es }
    : { title: entry.title_en, description: entry.description_en };
