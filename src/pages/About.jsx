
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
                        <h3 className="about-heading">South Americans' Secrets is a company focused on tourism and founded by expert guides of Peru.</h3>
                        <p className="about-text">
                        We are the most versatile tour guides of the south coast of Peru and operate directly in Paracas, Nazca and Arequipa. We are also based in Cusco and ready to serve with professional staff dedicated to our customers and foreign travel agents. Our experienced and knowledgable staff carefully track each and every arrival and departure and respond to our customers' needs with confidence and courtesy.
                        <br />
                        South Americans' Secrets was established in 2002 with the mission to create memorable experiences for all travelers alike. Our goal is to build trust and friendship with our guests, with social and environmental responsibility that aims to achieve sustainable and inclusive tourism. We understand that succesful experiences are about listening to our customers' needs and desires including custom programs, private travel, fixed departures, regional activities and special interest tours.
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
                                <h4 className="info__title-South">South Americans' Secrets</h4>
                                <p className="datos__title">Tourism Agency and Tour Operator</p>
                                <p className="datos__title">Amarilis Pereda & Lucio Hancco</p>
                                <p className="datos__title">St. Camino Real Mz D lt. 8 San Andrés</p>
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
                                <p><span>Gerardo Armejo </span>- Yacht keepers coordinator</p>
                                <p><span>Rossmery Albarrán</span>- Regional Manager</p>
                                <p><span>Lila Orellana</span>- Product and costing.</p>
                                <p><span>Diego Roca</span>- Tour guides coordinator</p>
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