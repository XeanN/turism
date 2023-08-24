
import React from "react";
import ServiceCard from "./ServiceCard";
import { Col } from "reactstrap";

import weatherImg from '../assets/images/weather.png'
import guideImg from '../assets/images/guide.png'
import customizationImg from '../assets/images/customization.png'

const serviceData = [
    {
        imgUrl: weatherImg,
        title: "Calculate Weather",
        desc: "Get accurate and current forecasts about the weather in your location. Plan your outdoor activities with confidence."

        
    },
    {
        imgUrl: guideImg,
        title: "Best Tour Guide",
        desc: "Discover exciting destinations and live unforgettable experiences with our expert tour guides. Explore amazing places."

        
    },
    {
        imgUrl: customizationImg,
        title: "Customization",
        desc: "Create experiences to suit you. Design your own adventures and enjoy to the fullest."

        
    }

];

const ServiceList = ()=> {
    return (
        <>
            {serviceData.map((item, index) => (
               <Col lg="3" md="6" sm="12" className="mb-4" key={index}>
                    <ServiceCard item={item} />
               </Col> 
            ))}
        </>
    );
};

export default ServiceList