// src/components/Featured-tours/FeaturedTourList.jsx
import React from "react";
import TourCard from "../../shared/TourCard";
import { Col } from "reactstrap";
import useFetch from "../../hooks/useFetch";
import { BASE_URL } from "../../utils/config";

const FeaturedTourList = () => {
  const { data: featuredTours, loading, error } = useFetch(`${BASE_URL}/getFeaturedTours`);

  if (loading) return <h4>Cargando...</h4>;
  if (error)   return <h4>{error}</h4>;
  if (!featuredTours.length) return <h4>No hay tours destacados</h4>;

  return (
    <>
      {featuredTours.map((tour) => (
        <Col lg="3" md="6" sm="6" className="mb-4" key={tour.id}>
          <TourCard tour={tour} />
        </Col>
      ))}
    </>
  );
};

export default FeaturedTourList;
