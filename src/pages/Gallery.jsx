
import React, { useState } from "react";
import { Helmet } from "react-helmet";
import Lightbox from "yet-another-react-lightbox";
import "yet-another-react-lightbox/styles.css";
import CommonSection from "../shared/CommonSection";
import "../styles/gallery.css";

const Gallery = () => {
  const [open, setOpen] = useState(false);
  const [index, setIndex] = useState(0);
//aca aumentamos la cantidad de imagenes
  const images = Array.from({ length: 52 }, (_, i) => ({
    src: `/images/gallery${i + 1}.jpeg`,
  }));

  return (
    <>
      <Helmet>
        <title>Galería de Fotos | Turismo Nautico Paracas</title>
        <meta
          name="description"
          content="Mira las mejores fotos de nuestros tours en Paracas: Islas Ballestas, dunas de Huacachina, yates y clientes disfrutando la costa sur del Perú."
        />
        <link rel="canonical" href="https://turismonauticoparacas.com/gallery" />
        <meta property="og:title" content="Galería de Fotos - Turismo Nautico Paracas" />
        <meta property="og:type" content="website" />
        <meta property="og:url" content="https://turismonauticoparacas.com/gallery" />
      </Helmet>
      <CommonSection title="Our best moments" />
      <section className="gallery">
        <div className="container gallery-grid">
          {images.map((img, i) => (
            <img
              key={i}
              src={img.src}
              alt={`Gallery ${i + 1}`}
              className="thumbnail"
              onClick={() => {
                setIndex(i);
                setOpen(true);
              }}
            />
          ))}
        </div>

        <Lightbox open={open} close={() => setOpen(false)} slides={images} index={index} />
      </section>
    </>
  );
};

export default Gallery;
