
import React from "react";
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



const About = ()=> {
    return <section>
         <CommonSection title={'About Us'}/>
        <div className="about-container">
            <Container>
                <Row>
                    <Col md={10} className="article-title">
                        <h3 className="about-heading">Turismo Nautico Paracas</h3>
                        <p className="about-text">
                        We are a travel agency and tour operator that provides tourism services in Paracas Peru, with high standards of quality and safety for our clients, satisfying their expectations with a staff of professionals with vast experience in tourism, providing advice for their choice of packages with competitive rates, offers tailored to each client using technological development to facilitate different payment channels. Versatile to the most demanding needs of each client.
                        </p>
                        <h3 className="about-h3">Mission</h3>
                        <p className="about-text">
                        Contribute to the development of tourism in our country, in a sustainable, environmentally friendly manner, providing quality services with added value, meeting the expectations of our clients as “a pleasant experience.”
                        </p>  
                        <h3 className="about-h3">Vision</h3>
                        <p className="about-text">
                        To be recognized as the best tourism company on the southern coast of Peru, committed to the development and innovation of service and quality for the benefit of our clients.
                        La Familia de TURISMO NAUTICO PARACAS cuenta con un staff de profesionales dedicados y certificados con los nuevos estándares, para garantizar una experiencia única, con la misión de brindar a nuestros clientes un excelente servicio de asesoría en turismo en la costa sur del Perú Desde ese momento, nos propusimos ser líderes, respetando principios, valores, éticos, profesionales, de respeto, de calidad y responsabilidad. En la actualidad contamos con profesionales en Turismo, capacitados constantemente con los más altos estándares que el turismo solicita.
                        </p>
                        <h3 className="about-heading">Why choose us</h3>
                        <h3 className="about-h3">We are in Paracas:</h3>
                        <p className="about-text">
                        We are direct administrators of water tourism vessels. For your convenience, we are a Local Agency, so we can solve any problem with ease.
                        </p>
                        <h3 className="about-h3">Best prices</h3>
                        <p className="about-text">
                        Being the direct administrators of water transportation, our policy is to provide the highest quality service at the lowest possible cost, you will always obtain transparency in all our tours.
                        </p> 
                        <h3 className="about-h3">Personalized Attention</h3>
                        <p className="about-text">
                        We always seek the comfort of our clients, they can contact us in person in Bahía de Paracas or through our digital communication channels.
                        </p> 
           

                        <Link to="/tours" className="about-button"> 
                            Explore Our Tours
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
                                <h4 className="info__title-South">Turismo Nautico Paracas</h4>
                                <p className="datos__title">Tourism Agency and Tour Operator</p>
                                <p className="datos__title">Amarilis Pereda & Lucio Hancco</p>
                                <p className="datos__title">A.H. Alberto Tataje Muñoz Mz "C" Lote 2, Paracas, Peru</p>
                                <p className="datos__title">Inside Marina Turística "Tourist Pier", right next to Hotel San Agustín - Paracas. Open 7:30 am to 1:00 pm (Paracas)</p>
                                <p className="datos__title">Cel:+51 956-481-002 / +51 947-058-508</p>
                            </div>
                        </Col>
                        <Col md={6}>
                            <div className="about-info white">
                                <h4 className="info__title-South">Our Team</h4>
                                <p><span>Lucio Hancco S. </span>- Tour advisor & tour guide</p>
                                <p><span>Amarilis Pereda </span>- Vessel operator.</p>
                                <p><span>Alberto Hernández </span>- Vessel operator 2</p>
                                <p><span>Juan Carlos Oyola </span>- Yacht keepers</p>
                                <p><span>Ilich Lenin Pereda </span>- Yacht keepers</p>
                                <p><span>Karl Kevin H. </span>- Yacht keepers</p>
                                <p><span>Rossmery Albarrán </span>- Regional Manager</p>
                                <p><span>Karol Hancco </span>- Product and Costing</p>
                                <p><span>Martin Vega </span>- Tour guides coordinator</p>
                                <p><span>Abilio Dextre</span>French tour guide</p>
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
                                <h3 className="title-black">Certificates of excellence</h3>
                                <div className="certificate-info col-md-8 col-sm-12 white">
                                    <div className="bg-imgs white tour-image ">
                                        <div>
                                            <img src={laguna} alt="" />
                                        </div>
                                        <div>
                                            <img src={south} alt="" />
                                        </div>
                                        <div >
                                            <img src={yate} alt="" />
                                        </div>
                                    </div>
                                    <div className="cert-imgs ">
                                        <div className="certs white">
                                            <img src={protection} alt="" />
                                        </div>
                                        <div className="certs">
                                            <img src={tripadvisor} alt="" />
                                        </div>
                                        <div className="certs">
                                            <img src={ultralow} alt="" />
                                        </div>
                                        <div className="certs">
                                            <img src={positiva} alt="" />
                                        </div>
                                    </div>
                                    <p>
                                    South Americans' Secrets was established in 2002 with the mission to create memorable experiences for all travelers alike. sixteen years after, we won the Tripadvisor certificate of excellence. All our ships have US EPA certificate, ranked as ultra-low emissions. Our Client is the priority, every boat trip customer is insurance with Positiva Seguros
                                    </p>

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