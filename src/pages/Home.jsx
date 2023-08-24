import React from "react";
import '../styles/home.css';

import { Container, Row, Col } from "reactstrap";
import heroImg from '../assets/images/machu_picchu_main.png'
import heroImg02 from '../assets/images/hero-img02.jpg'
import heroVideo from '../assets/images/hero-video.mp4'
import worldImg from '../assets/images/world.png'
import experienceImg from '../assets/images/experience.png'

import Subtitle from './../shared/Subtitle'

import SearchBar from "../shared/SearchBar";
import ServiceList from "../services/ServiceList";
import FeaturedTourList from "../components/Featured-tours/FeaturedTourList";
import MasonryImagesGallery from "../components/Image-gallery/MasonryImagesGallery";
import Testimonial from "../components/Testimonial/Testimonial";
import Newsletter from "../shared/Newsletter";


const Home = ()=> {
    return <>
    {/* ================hero section start==================== */}
    <section>
        <Container>
            <Row>
                <Col lg="6">
                    <div className="hero__content">
                        <div className="hero__subtitle d-flex align-items-center">
                            <Subtitle subtitle={'Know Before You Go'}/>
                            <img src={worldImg} alt="" />
                        </div>
                        <h1>
                            South American's Secrets{""}
                            <span className="highlight"> memories Peru</span>
                        </h1>
                        <p>
                            Fantastic tours and expert guides that help you make the most of your trip to Peru!
                        </p>
                    </div>
                </Col> 
              
                <Col lg='2'>
                    <div className="hero__img-box">
                        <img src={heroImg} alt="" />
                    </div>
                </Col>

                <Col lg='2'>
                    <div className="hero__img-box hero__video-box mt-4">
                        <video src={heroVideo} alt="" controls/>
                    </div>
                </Col>

                <Col lg='2'>
                    <div className="hero__img-box mt-5">
                        <img src={heroImg02} alt="" />
                    </div>
                </Col>

                <SearchBar/>
            </Row>
        </Container>  
    </section>
    {/* ================hero section start==================== */}
    <section>
        <Container>
            <Row>
                <Col lg='3'>
                    <h5 className="services__subtitle">What we serve</h5>
                    <h2 className="services__title">We offer our best services</h2>
                </Col>
                <ServiceList/>
            </Row>
        </Container>
    </section>

    {/* ================featured section start==================== */}
    <section>
        <Container>
            <Row >
                <Col lg="12" className="mb-5">
                    <Subtitle subtitle={'Explore'}/>
                    <h2 className="featured__tour-title">Our featured tours</h2>
                </Col>
                <FeaturedTourList/>
            </Row>
        </Container>
    </section>
    {/* ================featured section end==================== */}
    {/* ================ experience section start ==================== */}
    <section>
        <Container>
            <Row>
                <Col lg="6">
                    <div className="experience__content">
                        <Subtitle subtitle={'Experience'}/>

                        <h2>With our all experience <br />we will serve you</h2>
                        <p>
                            South Americans' Secrets is a company focused on tourism and
                            <br />
                            founded by expert guides of Peru.
                        </p>
                    </div>

                    <div className="counter__wrapper d-flex align-items-center gap-5
                    ">
                        <div className="counter__box">
                            <span>10k+</span>
                            <h6>Successful trip</h6>
                        </div>

                        <div className="counter__box">
                            <span>4k+</span>
                            <h6>Regular clients</h6>
                        </div>

                        <div className="counter__box">
                            <span>21</span>
                            <h6>Years experience</h6>
                        </div>
                    </div>
                </Col>

                <Col lg="6">
                   <div className="experience__img">
                        <img src={experienceImg} alt="" />
                    </div> 
                </Col>
            </Row>
        </Container>
    </section>
    {/* ================ experience section end ==================== */}

    {/* ================ gallery section start ==================== */}
    <section>
        <Container>
            <Row>
                <Col lg="12">
                    <Subtitle subtitle={'Gallery'}/>
                    <h2 className="gallery_title">
                        Visit our customers tour gallery
                    </h2>
                </Col>
                <Col lg="12">
                    <MasonryImagesGallery/>
                </Col>
            </Row>
        </Container>
    </section>
    {/* ================ gallery section end ==================== */}

    {/* ================ testimonial section start ==================== */}
    <section>
        <Container>
            <Row>
                <Col lg="12">
                    <Subtitle subtitle={'Clients'}/>
                    <h2 className="testimonial__title">Discover What Our Clients Have to Say</h2>
                </Col>

                <Col lg="12">
                    <Testimonial/>
                </Col>
            </Row>
        </Container>
    </section>
    {/* ================ testimonial section end ==================== */}
    <Newsletter/>
    </>
};

export default Home
