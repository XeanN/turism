// src/pages/Tours.jsx
import React, { useState, useEffect } from "react";
import CommonSection from "../shared/CommonSection";
import TourCard from "../shared/TourCard";
import SearchBar from "../shared/SearchBar";
import Newsletter from "../shared/Newsletter";
import useFetch from "../hooks/useFetch";
import { BASE_URL } from "../utils/config";
//import { API_ENDPOINTS } from "../utils/config";
import { Container, Row, Col } from "reactstrap";

const Tours = () => {
  const [page, setPage] = useState(0);

  const { data: tours, loading, error } = useFetch(`${BASE_URL}/getAllTours&page=${page}`);
  const { data: countArr } = useFetch(`${BASE_URL}/getTotalTours`);
  const tourCount = countArr[0]?.total || 1;
  const pageCount = Math.ceil(tourCount / 8);


  useEffect(() => { window.scrollTo(0, 0); }, [page]);

  return (
    <>
      <CommonSection title="All Tours" />
      <section>
        <Container><Row><SearchBar /></Row></Container>
      </section>
      <section className="pt-0">
        <Container>
          {loading && <h4 className="text-center pt-5">Loading...</h4>}
          {error   && <h4 className="text-center pt-5">{error}</h4>}
          {!loading && !error && (
            <Row>
              {tours.map((tour) => (
                <Col lg="3" md="6" sm="6" className="mb-4" key={tour.id}>
                  <TourCard tour={tour} />
                </Col>
              ))}
              <Col lg="12">
                <div className="pagination d-flex justify-content-center gap-3 mt-4">
                  {Array.from({ length: pageCount }).map((_, i) => (
                    <span
                      key={i}
                      className={i === page ? "active__page" : ""}
                      onClick={() => setPage(i)}
                    >{i + 1}</span>
                  ))}
                </div>
              </Col>
            </Row>
          )}
        </Container>
      </section>
      <Newsletter />
    </>
  );
};

export default Tours;
