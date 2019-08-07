module.exports = function(grunt) {

	// Display stats
	require('time-grunt')(grunt);
	var webpack = require("webpack");
	var webpackConfig = require("./webpack.config.js");

	grunt.initConfig({
		typescript: {
			base: {
				src: ['src/**/*.ts'],
				dest: './',
				options: {
					module: 'amd',
					target: 'es5',
					sourceMap: true,
					generateTsConfig: true
				}
			}
		},
		tslint: {
			options: {
				configuration: "tslint.json"
			},
			files: {
				src: ['src/**/*.ts']
			}
		},
		sass: {
			options: {
				sourceMap: true,
				outputStyle: 'compressed'
			},
			dev: {
				files: {
					'dist/style.css': 'css/**/*.scss'
				}
			},
		},
		watch: {
			grunt: {
				files: [
					'Gruntfile.js'
				],
				options: {
					reload: true
				}
			},
			typescript: {
				files: 'src/**/*.ts',
				tasks: [
					'typescript',
					'webpack:build-dev',
					'tslint'
				]
			},
			css: {
				files: 'css/**/*.scss',
				tasks: [
					'sass'
				]
			}
		},
		webpack: {
			options: webpackConfig,
			"build-release": {
				plugins: webpackConfig.plugins.concat(
					new webpack.optimize.UglifyJsPlugin()
				)
			},
			"build-dev": {
				debug: true,
				devtool: "sourcemap"
			}
		}
	});

	grunt.loadNpmTasks('grunt-typescript');
	grunt.loadNpmTasks('grunt-sass');
	grunt.loadNpmTasks('grunt-contrib-watch');
	grunt.loadNpmTasks("grunt-tslint");
	grunt.loadNpmTasks("grunt-webpack");

	// Compile in dev mode and wait.
	grunt.registerTask('default', [
		'typescript',
		'sass',
		'webpack:build-dev',
		'watch'
	]);
	
	// Compile in release mode.
	grunt.registerTask('release', [
		'typescript',
		'sass',
		'webpack:build-release'
	]);
};