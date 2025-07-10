
import React, { useState } from "react";
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
