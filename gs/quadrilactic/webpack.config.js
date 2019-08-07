
var path = require("path");
module.exports = {
	entry: "./src/main.js",
	devtool: "source-map",
	output: {
		path: path.join(__dirname, "dist"),
		publicPath: "dist/",
		filename: "bundle.js"
	},
	resolve: {
		root: [
			path.resolve("./src"),
		],
		moduleDirectories: [
			"web_modules",
			"node_modules"
		]
	},
	module: {
		preLoaders: [
			{
				test:   /\.js$/,
				loader: 'source-map-loader'
			}
		]
	},
	plugins: [
	]
};