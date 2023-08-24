

import React from "react";
import Slider from 'react-slick';
import wendyW from '../../assets/images/wendy-w.jpg'
import kevinK from '../../assets/images/kevin-k.JPG'
import fernanda from '../../assets/images/fernanda.jpg'

const Testimonial = ()=> {

        const settings={
            dots: true,
            infinite: true,
            autoplay: true,
            speed: 1000,
            swipeToSlide: true,
            autoplaySpeed: 2000,
            slidesToShow: 3,

            responsive:[
                {
                    breakpoint: 992,
                    settings:{
                        slidesToShow: 2,
                        slidesToScroll: 1,
                        infinite: true,
                        dots: true,
                    },
                },
                    {
                        breakpoint:576,
                        settings:{
                            slidesToShow: 1,
                            slidesToScroll: 1,
                        },
                    },
                
            ],
        }

    return (
        <Slider {...settings}>
            <div className="testimonial py-4 px-3">
                <p>
                Several of us off the Volendam arranged for a tour out to the Ballestas Island and Paracas Reserve-we had a wonderful trip. The company is friendly and professional to deal with and exceeded all our expectations. The boat ride out and around the islands was great and the Pisco Sour to follow afterwards was even better.
                </p>
                <div className="d-flex align-items-center-gap-4 mt-3">
                    <img src={wendyW} className="w-25 h-25 rounded-2" alt="" />
                    <div>
                        <h6 className="mb-0 mt-3">Wendy W.</h6>
                        <p>Customer</p>
                    </div>
                </div>
            </div>

            <div className="testimonial py-4 px-3">
                <p>
                We booked a trip to the " Band of Holes" and Tambo Colorado with Lucio and it was amazing! Our guide Diego showed up ahead of time and totally wowed my wife and I with his knowledge and enthusiasm for both areas. We highly recommend Lucio and Diego for any of your adventures in Peru.
                </p>
                <div className="d-flex align-items-center-gap-4 mt-3">
                    <img src={kevinK} className="w-25 h-25 rounded-2" alt="" />
                    <div>
                        <h6 className="mb-0 mt-3">Kevin K.</h6>
                        <p>Customer</p>
                    </div>
                </div>
            </div>

            <div className="testimonial py-4 px-3">
                <p>
                We were on a cruise ship and took the Ballestas Islands and Paracas Nature Reserve tours with this company. Liz was our guide and she was very good. They picked us up at the harbor and it was very convenient. Our group was on our own boat for the ride to and around the Ballestas Islands.
                </p>
                <div className="d-flex align-items-center-gap-4 mt-3">
                    <img src={fernanda} className="w-25 h-25 rounded-2" alt="" />
                    <div>
                        <h6 className="mb-0 mt-3">FernandaGirl</h6>
                        <p>Customer</p>
                    </div>
                </div>
            </div>

            {/* Esto esta para actualizar los datos P, imagenes y nombres */}
            <div className="testimonial py-4 px-3">
                <p>
                Several of us off the Volendam arranged for a tour out to the Ballestas Island and Paracas Reserve-we had a wonderful trip. The company is friendly and professional to deal with and exceeded all our expectations. The boat ride out and around the islands was great and the Pisco Sour to follow afterwards was even better.
                </p>
                <div className="d-flex align-items-center-gap-4 mt-3">
                    <img src={wendyW} className="w-25 h-25 rounded-2" alt="" />
                    <div>
                        <h6 className="mb-0 mt-3">Wendy W.</h6>
                        <p>Customer</p>
                    </div>
                </div>
            </div>

            <div className="testimonial py-4 px-3">
                <p>
                We booked a trip to the " Band of Holes" and Tambo Colorado with Lucio and it was amazing! Our guide Diego showed up ahead of time and totally wowed my wife and I with his knowledge and enthusiasm for both areas. We highly recommend Lucio and Diego for any of your adventures in Peru.
                </p>
                <div className="d-flex align-items-center-gap-4 mt-3">
                    <img src={kevinK} className="w-25 h-25 rounded-2" alt="" />
                    <div>
                        <h6 className="mb-0 mt-3">Kevin K.</h6>
                        <p>Customer</p>
                    </div>
                </div>
            </div>

            <div className="testimonial py-4 px-3">
                <p>
                We were on a cruise ship and took the Ballestas Islands and Paracas Nature Reserve tours with this company. Liz was our guide and she was very good. They picked us up at the harbor and it was very convenient. Our group was on our own boat for the ride to and around the Ballestas Islands.
                </p>
                <div className="d-flex align-items-center-gap-4 mt-3">
                    <img src={fernanda} className="w-25 h-25 rounded-2" alt="" />
                    <div>
                        <h6 className="mb-0 mt-3">FernandaGirl</h6>
                        <p>Customer</p>
                    </div>
                </div>
            </div>
        </Slider>
    )
}

export default Testimonial