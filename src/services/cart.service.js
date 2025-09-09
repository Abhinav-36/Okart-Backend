const httpStatus = require("http-status");
const { Cart, Product } = require("../models");
const ApiError = require("../utils/ApiError");
const config = require("../config/config");
const { getProductById } = require("./product.service");

// TODO: CRIO_TASK_MODULE_CART - Implement the Cart service methods

/**
 * Fetches cart for a user
 * - Fetch user's cart from Mongo
 * - If cart doesn't exist, throw ApiError
 * --- status code  - 404 NOT FOUND
 * --- message - "User does not have a cart"
 *
 * @param {User} user
 * @returns {Promise<Cart>}
 * @throws {ApiError}
 */
const getCartByUser = async (user) => {
    let cart = await Cart.findOne({email:user.email})
    if(!cart){
      throw new ApiError(httpStatus.NOT_FOUND,"User does not have a cart");
    }
  return cart;
};

/**
 * Adds a new product to cart
 * - Get user's cart object using "Cart" model's findOne() method
 * --- If it doesn't exist, create one
 * --- If cart creation fails, throw ApiError with "500 Internal Server Error" status code
 *
 * - If product to add already in user's cart, throw ApiError with
 * --- status code  - 400 BAD REQUEST
 * --- message - "Product already in cart. Use the cart sidebar to update or remove product from cart"
 *
 * - If product to add not in "products" collection in MongoDB, throw ApiError with
 * --- status code  - 400 BAD REQUEST
 * --- message - "Product doesn't exist in database"
 *
 * - Otherwise, add product to user's cart
 *
 *
 *
 * @param {User} user
 * @param {string} productId
 * @param {number} quantity
 * @returns {Promise<Cart>}
 * @throws {ApiError}
 */
 const addProductToCart = async (user, productId, quantity) => {
    let cart = await Cart.findOne({ email: user.email });

    const product = await getProductById(productId);
    if (!product) {
      throw new ApiError(httpStatus.BAD_REQUEST, "Product doesn't exist in database");
    }

    // Case 1: New cart
    if (!cart) {
      const createdCart = await Cart.create({
        email: user.email,
        cartItems: [{ product, quantity }],
      });
    
      if (!createdCart) {
        throw new ApiError(
          httpStatus.INTERNAL_SERVER_ERROR,
          "Failed to add product to cart"
        );
      }
    
      return createdCart;
    }

    // Case 2: Product already in cart
    const productInCart = cart.cartItems.findIndex((item) => {
      const cartProductId =
        item.product && item.product._id
          ? item.product._id.toString()
          : item.product.toString();
    
      return cartProductId === product._id.toString(); // ✅ match DB object IDs
    });
    

    if (productInCart > -1) {
      throw new ApiError(
        httpStatus.BAD_REQUEST,
        "Product already in cart. Use the cart sidebar to update or remove product from cart"
      );
      return;
    }

    // Case 3: Add new product
    cart.cartItems.push({ product, quantity });
    await cart.save();
    return cart; // ✅ return cart directly, not result of save
};


/**
 * Updates the quantity of an already existing product in cart
 * - Get user's cart object using "Cart" model's findOne() method
 * - If cart doesn't exist, throw ApiError with
 * --- status code  - 400 BAD REQUEST
 * --- message - "User does not have a cart. Use POST to create cart and add a product"
 *
 * - If product to add not in "products" collection in MongoDB, throw ApiError with
 * --- status code  - 400 BAD REQUEST
 * --- message - "Product doesn't exist in database"
 *
 * - If product to update not in user's cart, throw ApiError with
 * --- status code  - 400 BAD REQUEST
 * --- message - "Product not in cart"
 *
 * - Otherwise, update the product's quantity in user's cart to the new quantity provided and return the cart object
 *
 *
 * @param {User} user
 * @param {string} productId
 * @param {number} quantity
 * @returns {Promise<Cart>
 * @throws {ApiError}
 */
const updateProductInCart = async (user, productId, quantity) => {
  let cart = await Cart.findOne({email:user.email});
  if(!cart){
    throw new ApiError(httpStatus.BAD_REQUEST,
    "User does not have a cart. Use POST to create cart and add a product");
  }
  let product = await getProductById(productId);
  if (!product) throw new ApiError(httpStatus.BAD_REQUEST, "Product doesn't exist in database");

  const productIndex = cart.cartItems.findIndex((item) =>
    item.product._id.equals(product._id)
  );

  if(productIndex === -1){
    throw new ApiError(httpStatus.BAD_REQUEST,"Product not in cart");
  }

  cart.cartItems[productIndex].quantity = quantity;
  await cart.save();
  return cart;

};

/**
 * Deletes an already existing product in cart
 * - If cart doesn't exist for user, throw ApiError with
 * --- status code  - 400 BAD REQUEST
 * --- message - "User does not have a cart"
 *
 * - If product to update not in user's cart, throw ApiError with
 * --- status code  - 400 BAD REQUEST
 * --- message - "Product not in cart"
 *
 * Otherwise, remove the product from user's cart
 *
 *
 * @param {User} user
 * @param {string} productId
 * @throws {ApiError}
 */
const deleteProductFromCart = async (user, productId) => {
  let cart = await Cart.findOne({email:user.email})
  if(!cart){
    throw new ApiError(httpStatus.BAD_REQUEST, "User does not have a cart");
  }

  const productIndex = cart.cartItems.findIndex((item) =>
    item.product._id.equals(productId)
  );

  if(productIndex === -1){
    throw new ApiError(httpStatus.BAD_REQUEST,"Product not in cart");
  }

  cart.cartItems.splice(productIndex,1);

  await cart.save();
  return cart;
};

// TODO: CRIO_TASK_MODULE_TEST - Implement checkout function
/**
 * Checkout a users cart.
 * On success, users cart must have no products.
 *
 * @param {User} user
 * @returns {Promise}
 * @throws {ApiError} when cart is invalid
 */
const checkout = async (user) => {
  const cart = await Cart.findOne({email: user.email});
  if(!cart){
    throw new ApiError(httpStatus.NOT_FOUND,"Cart not found");
  }

  if(cart.cartItems.length === 0){
    throw new ApiError(httpStatus.BAD_REQUEST, "Cart is Empty");
  }

  if(!(await user.hasSetNonDefaultAddress())){
    throw new ApiError(httpStatus.BAD_REQUEST, "Please set the default address");
  }

  let totalCartValue = cart.cartItems.reduce((sum, { product, quantity }) => sum + product.cost * quantity,0)

  // console.log(totalCartValue);

  if(totalCartValue > user.walletMoney){
    throw new ApiError(httpStatus.BAD_REQUEST, "Insuffiecient Balance.")
  }
  user.walletMoney -= totalCartValue;
  user.save();
  cart.cartItems = [];
  cart.save();
};

module.exports = {
  getCartByUser,
  addProductToCart,
  updateProductInCart,
  deleteProductFromCart,
  checkout,
};
