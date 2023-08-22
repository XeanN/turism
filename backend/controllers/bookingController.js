import Booking from '../models/Booking.js';

// create new booking
export const createBooking =async(req, res)=> {
    const newBooking = new Booking(req.body);

    try {
        const savedBooking = await newBooking.save();

        res.status(200).json({ success: true, message: "Your tour is Booked", data: savedBooking});
    } catch (error) {
        res.status(500).json({ success: false, message:"internal server error"});
    };
};
//get single Booking
export const getBooking = async(req, res)=> {
    const id = req.params.id;

    try {
        const book = await Booking.findById(id);

        res.status(200).json({success: true, message: "successful", data: book});
    } catch (error) {
        res.status(404).json({ success: false, message: "not found"});
    };
};

//get all Booking
export const getAllBooking = async(req, res)=> {

    try {
        const books = await Booking.find();

        res.status(200).json({success: true, message: "successful", data: books});
    } catch (error) {
        res.status(500).json({ success: false, message: "internal server error -getAllBooking"});
    };
};