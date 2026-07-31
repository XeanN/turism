
import React from "react";
import { Helmet } from "react-helmet";
import { Container, Row, Col } from 'reactstrap';
import CommonSection from "../shared/CommonSection";
import Newsletter from './../shared/Newsletter'
import { Link } from 'react-router-dom';
import '../styles/about.css';
import laguna from '../assets/images/about/laguna.jpg'
import south from '../assets/images/about/southAmerican.jpg'
import yate from '../assets/images/about/yate-turistico.jpg'
import protection from '../assets/images/about/protection.png';
import tripadvisor from '../assets/images/about/tripadvisor.jpg';
import ultralow from '../assets/images/about/ultralow.png';
import positiva from '../assets/images/about/laPositiva.jpg';
import { useLanguage, withLang } from '../context/LanguageContext';

const text = {
  en: {
    metaTitle: "About Us | Turismo Nautico Paracas",
    metaDescription: "Meet Turismo Nautico Paracas: a local agency with over 20 years of experience, direct administrators of tourist vessels in Paracas, Peru.",
    pageTitle: "About Us",
    heading: "Turismo Nautico Paracas",
    intro: "We are a travel agency and tour operator that provides tourism services in Paracas Peru, with high standards of quality and safety for our clients, satisfying their expectations with a staff of professionals with vast experience in tourism, providing advice for their choice of packages with competitive rates, offers tailored to each client using technological development to facilitate different payment channels. Versatile to the most demanding needs of each client.",
    mission: "Mission",
    missionText: "Contribute to the development of tourism in our country, in a sustainable, environmentally friendly manner, providing quality services with added value, meeting the expectations of our clients as “a pleasant experience.”",
    vision: "Vision",
    visionText: "To be recognized as the best tourism company on the southern coast of Peru, committed to the development and innovation of service and quality for the benefit of our clients. The Turismo Nautico Paracas family has a staff of dedicated professionals certified to the newest standards, to guarantee a unique experience, with the mission of providing our clients an excellent tourism advisory service on the southern coast of Peru. Since then, we set out to be leaders, respecting ethical, professional, respectful, quality and responsible principles and values. Today we have tourism professionals, constantly trained to the highest standards that tourism demands.",
    whyChooseUs: "Why choose us",
    inParacas: "We are in Paracas:",
    inParacasText: "We are direct administrators of water tourism vessels. For your convenience, we are a Local Agency, so we can solve any problem with ease.",
    bestPrices: "Best prices",
    bestPricesText: "Being the direct administrators of water transportation, our policy is to provide the highest quality service at the lowest possible cost, you will always obtain transparency in all our tours.",
    personalizedAttention: "Personalized Attention",
    personalizedAttentionText: "We always seek the comfort of our clients, they can contact us in person in Bahía de Paracas or through our digital communication channels.",
    exploreTours: "Explore Our Tours",
    agencyType: "Tourism Agency and Tour Operator",
    address: 'A.H. Alberto Tataje Muñoz Mz "C" Lote 2, Paracas, Peru',
    location: 'Inside Marina Turística "Tourist Pier", right next to Hotel San Agustín - Paracas. Open 7:30 am to 1:00 pm (Paracas)',
    ourTeam: "Our Team",
    team: [
      { name: "Lucio Hancco S.", role: "Tour advisor & tour guide" },
      { name: "Amarilis Pereda", role: "Vessel operator." },
      { name: "Alberto Hernández", role: "Vessel operator 2" },
      { name: "Juan Carlos Oyola", role: "Yacht keepers" },
      { name: "Ilich Lenin Pereda", role: "Yacht keepers" },
      { name: "Karl Kevin H.", role: "Yacht keepers" },
      { name: "Rossmery Albarrán", role: "Regional Manager" },
      { name: "Karol Hancco", role: "Product and Costing" },
      { name: "Martin Vega", role: "Tour guides coordinator" },
      { name: "Abilio Dextre", role: "French tour guide" },
    ],
    certificates: "Certificates of excellence",
    certificatesText: "South Americans' Secrets was established in 2002 with the mission to create memorable experiences for all travelers alike. Sixteen years after, we won the Tripadvisor certificate of excellence. All our ships have US EPA certificate, ranked as ultra-low emissions. Our Client is the priority, every boat trip customer is insured with Positiva Seguros.",
  },
  es: {
    metaTitle: "Sobre Nosotros | Turismo Nautico Paracas",
    metaDescription: "Conoce a Turismo Nautico Paracas: agencia local con más de 20 años de experiencia, administradores directos de embarcaciones turísticas en Paracas, Perú.",
    pageTitle: "Sobre Nosotros",
    heading: "Turismo Nautico Paracas",
    intro: "Somos una agencia de viajes y operador turístico que brinda servicios de turismo en Paracas, Perú, con altos estándares de calidad y seguridad para nuestros clientes, satisfaciendo sus expectativas con un staff de profesionales con amplia experiencia en turismo, asesorando en la elección de paquetes con tarifas competitivas, ofertas a la medida de cada cliente usando desarrollo tecnológico para facilitar distintos canales de pago. Versátiles ante las necesidades más exigentes de cada cliente.",
    mission: "Misión",
    missionText: "Contribuir al desarrollo del turismo en nuestro país, de manera sostenible y amigable con el medio ambiente, brindando servicios de calidad con valor agregado, cumpliendo las expectativas de nuestros clientes como “una experiencia agradable”.",
    vision: "Visión",
    visionText: "Ser reconocidos como la mejor empresa de turismo de la costa sur del Perú, comprometidos con el desarrollo e innovación del servicio y la calidad en beneficio de nuestros clientes. La Familia de Turismo Nautico Paracas cuenta con un staff de profesionales dedicados y certificados con los nuevos estándares, para garantizar una experiencia única, con la misión de brindar a nuestros clientes un excelente servicio de asesoría en turismo en la costa sur del Perú. Desde ese momento, nos propusimos ser líderes, respetando principios y valores éticos, profesionales, de respeto, calidad y responsabilidad. En la actualidad contamos con profesionales en turismo, capacitados constantemente con los más altos estándares que el turismo exige.",
    whyChooseUs: "Por qué elegirnos",
    inParacas: "Estamos en Paracas:",
    inParacasText: "Somos administradores directos de embarcaciones de turismo acuático. Para tu comodidad, somos una agencia local, así que podemos resolver cualquier inconveniente con facilidad.",
    bestPrices: "Mejores precios",
    bestPricesText: "Al ser administradores directos del transporte acuático, nuestra política es brindar el servicio de mayor calidad al menor costo posible; siempre obtendrás transparencia en todos nuestros tours.",
    personalizedAttention: "Atención Personalizada",
    personalizedAttentionText: "Siempre buscamos la comodidad de nuestros clientes, quienes pueden contactarnos en persona en la Bahía de Paracas o a través de nuestros canales de comunicación digital.",
    exploreTours: "Explora Nuestros Tours",
    agencyType: "Agencia de Turismo y Operador de Tours",
    address: 'A.H. Alberto Tataje Muñoz Mz "C" Lote 2, Paracas, Perú',
    location: 'Dentro de la Marina Turística "Muelle Turístico", al lado del Hotel San Agustín - Paracas. Abierto de 7:30 am a 1:00 pm (Paracas)',
    ourTeam: "Nuestro Equipo",
    team: [
      { name: "Lucio Hancco S.", role: "Asesor de tours y guía turístico" },
      { name: "Amarilis Pereda", role: "Operadora de embarcación." },
      { name: "Alberto Hernández", role: "Operador de embarcación 2" },
      { name: "Juan Carlos Oyola", role: "Cuidador de yate" },
      { name: "Ilich Lenin Pereda", role: "Cuidador de yate" },
      { name: "Karl Kevin H.", role: "Cuidador de yate" },
      { name: "Rossmery Albarrán", role: "Gerente Regional" },
      { name: "Karol Hancco", role: "Producto y Costos" },
      { name: "Martin Vega", role: "Coordinador de guías" },
      { name: "Abilio Dextre", role: "Guía turístico en francés" },
    ],
    certificates: "Certificados de excelencia",
    certificatesText: "South Americans' Secrets se fundó en 2002 con la misión de crear experiencias memorables para todos los viajeros. Dieciséis años después, ganamos el certificado de excelencia de Tripadvisor. Todas nuestras embarcaciones cuentan con certificado US EPA, clasificadas como de emisiones ultra bajas. Nuestro cliente es la prioridad: cada pasajero de nuestros tours en bote cuenta con seguro de Positiva Seguros.",
  },
};

const About = () => {
    const lang = useLanguage();
    const t = text[lang];
    const canonicalUrl = lang === "es"
      ? "https://turismonauticoparacas.com/es/about"
      : "https://turismonauticoparacas.com/about";

    return <section>
         <Helmet>
            <title>{t.metaTitle}</title>
            <meta name="description" content={t.metaDescription} />
            <link rel="canonical" href={canonicalUrl} />
            <link rel="alternate" hrefLang="en" href="https://turismonauticoparacas.com/about" />
            <link rel="alternate" hrefLang="es" href="https://turismonauticoparacas.com/es/about" />
            <link rel="alternate" hrefLang="x-default" href="https://turismonauticoparacas.com/about" />
            <meta property="og:title" content={t.metaTitle} />
            <meta property="og:description" content={t.metaDescription} />
            <meta property="og:type" content="website" />
            <meta property="og:url" content={canonicalUrl} />
         </Helmet>
         <CommonSection title={t.pageTitle}/>
        <div className="about-container">
            <Container>
                <Row>
                    <Col md={10} className="article-title">
                        <h3 className="about-heading">{t.heading}</h3>
                        <p className="about-text">{t.intro}</p>
                        <h3 className="about-h3">{t.mission}</h3>
                        <p className="about-text">{t.missionText}</p>
                        <h3 className="about-h3">{t.vision}</h3>
                        <p className="about-text">{t.visionText}</p>
                        <h3 className="about-heading">{t.whyChooseUs}</h3>
                        <h3 className="about-h3">{t.inParacas}</h3>
                        <p className="about-text">{t.inParacasText}</p>
                        <h3 className="about-h3">{t.bestPrices}</h3>
                        <p className="about-text">{t.bestPricesText}</p>
                        <h3 className="about-h3">{t.personalizedAttention}</h3>
                        <p className="about-text">{t.personalizedAttentionText}</p>

                        <Link to={withLang("/tours", lang)} className="about-button">
                            {t.exploreTours}
                        </Link>
                    </Col>

                </Row>
            </Container>

        </div>
        <div className="about-info-container">
                <Container>
                    <Row>
                        <Col md={6}>
                            <div className="about-info white">
                                <h4 className="info__title-South">{t.heading}</h4>
                                <p className="datos__title">{t.agencyType}</p>
                                <p className="datos__title">Amarilis Pereda & Lucio Hancco</p>
                                <p className="datos__title">{t.address}</p>
                                <p className="datos__title">{t.location}</p>
                                <p className="datos__title">Cel:+51 956-481-002 / +51 947-058-508</p>
                            </div>
                        </Col>
                        <Col md={6}>
                            <div className="about-info white">
                                <h4 className="info__title-South">{t.ourTeam}</h4>
                                {t.team.map((member) => (
                                  <p key={member.name}><span>{member.name} </span>- {member.role}</p>
                                ))}
                            </div>
                        </Col>
                    </Row>
                </Container>
            </div>
            <div>
                <Container>
                    <Row>
                        <Col>
                            <div className="row tour-container">
                                <h3 className="title-black">{t.certificates}</h3>
                                <div className="certificate-info col-md-8 col-sm-12 white">
                                    <div className="bg-imgs white tour-image ">
                                        <div>
                                            <img src={laguna} alt="Laguna en Paracas, Perú" />
                                        </div>
                                        <div>
                                            <img src={south} alt="Turismo Nautico Paracas, agencia de turismo en Sudamérica" />
                                        </div>
                                        <div >
                                            <img src={yate} alt="Yate turístico de Turismo Nautico Paracas" />
                                        </div>
                                    </div>
                                    <div className="cert-imgs ">
                                        <div className="certs white">
                                            <img src={protection} alt="Certificado de protección ambiental" />
                                        </div>
                                        <div className="certs">
                                            <img src={tripadvisor} alt="Certificado de excelencia Tripadvisor" />
                                        </div>
                                        <div className="certs">
                                            <img src={ultralow} alt="Certificado de emisiones ultra bajas EPA" />
                                        </div>
                                        <div className="certs">
                                            <img src={positiva} alt="Seguro La Positiva" />
                                        </div>
                                    </div>
                                    <p>{t.certificatesText}</p>

                                </div>
                            </div>
                        </Col>
                    </Row>
                </Container>
            </div>
        <Newsletter/>
    </section>
}


export default About
