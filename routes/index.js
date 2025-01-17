var express = require('express');
var router = express.Router();

const todoController = require('../controllers/todoController');
const userController = require('../controllers/userController');

function addUserToViews(req, res, next){
    if (req.user){
        res.locals.user = req.user;
    }
    next();
}

function redirectGuests(req, res, next){
    if(!req.user){
        res.redirect('/login');
    } else {
        next();
    }
}

/* GET home page. */
router.get('/', addUserToViews, redirectGuests, todoController.listAll);


router.get('/item/add',  todoController.displayAddItem);
router.post('/item/add',  todoController.addNewItem);

router.get('/item/edit/:id',  todoController.viewEditItem);
router.post('/item/edit/:id',  todoController.saveEditItem);

router.get('/item/delete/:id',  todoController.deleteItem);
router.get('/item/complete/:id',  todoController.makeItemComplete);
router.get('/item/incomplete/:id',  todoController.markItemIncomplete);

router.get('/register', userController.renderRegistration);
router.post('/register', userController.register);

router.get('/login', userController.renderLogin);
router.post('/login', userController.authenticate);

router.get('/logout', userController.logout);
module.exports = router;
