import {Player} from "player";
import {Controller} from "controller";
import {MovingPoint, Point} from "point";
import {Collider} from "collider";
import {Scoreboard} from "scoreboard";
import {Background} from "background";
import {Viewport} from "viewport";
import {Sound} from "sound";
import {Menu} from "menu";
import {Volume} from "volume";
import {Platform} from "platform";

export class Renderer {
	// Constants
	private static defaultGravity: number = 0.2;
	private static gameWidth: number = 480;
	private static minimumPlatformReboundSpeed: number = 10;
	private static timescale: number = 16;

	// Rendering references
	private canvas: HTMLCanvasElement;
	private context: CanvasRenderingContext2D;

	// State
	private isRunning: boolean = false;
	private player: Player;
	private platform: Platform;
	private scoreboard: Scoreboard;
	private background: Background;
	private menu: Menu;
	private viewport: Viewport;
	private lastTimestamp: number;
	private lastFps: number;
	private backgroundMusic: Sound;
	private deathSound: Sound;
	private volume: Volume;
	private controller: Controller;

	constructor(canvas: HTMLCanvasElement, controller: Controller) {
		this.canvas = canvas;
		this.context = canvas.getContext("2d");
		this.controller = controller;

		this.volume = new Volume(
			{
				x: this.canvas.width,
				y: this.canvas.height
			},
			controller);

		this.backgroundMusic = this.volume.createSound("snd/music.wav", { isLooping: true });
		this.backgroundMusic.play();

		this.deathSound = this.volume.createSound("snd/death.wav", {});

		let playerPosition: MovingPoint = {
			dX: 2,
			dY: -2,
			x: 30,
			y: 110
		};
		let playerDimensions: Point = {
			x: 30,
			y: 30
		};
		this.player = new Player(
			playerPosition,
			playerDimensions,
			"#FF0000",
			controller,
			Renderer.defaultGravity,
			Renderer.gameWidth,
			this.volume);

		this.background = new Background(
			{ x: 0, y: 0 },
			{ x: this.canvas.width, y: this.canvas.height },
			"#222222",
			this.player
		);

		let platformPosition: MovingPoint = {
			dX: 2,
			dY: 2,
			x: 30,
			y: 690
		};
		let platformDimensions: Point = {
			x: 90,
			y: 20
		};
		this.platform = new Platform(
			platformPosition,
			platformDimensions,
			"#FFFFFF",
			-Renderer.defaultGravity,
			this.volume,
			Renderer.gameWidth);
		this.platform.onBounce = () => {
			if (this.platform.ySpeed < Renderer.minimumPlatformReboundSpeed) {
				this.platform.ySpeed = Renderer.minimumPlatformReboundSpeed;
			}
		};

		let scoreboardPosition: MovingPoint = {
			dX: 0,
			dY: 0,
			x: 20,
			y: 370
		};
		let scoreboardDimensions: Point = {
			x: 0,
			y: 0
		};
		this.scoreboard = new Scoreboard(
			this.player,
			scoreboardPosition,
			scoreboardDimensions,
			"rgba(255,255,255, 0.1)"
		);

		this.menu = new Menu(
			{
				x: this.canvas.width,
				y: this.canvas.height
			},
			controller,
			this.background,
			() => {
				this.player.Reset();
				this.platform.Reset();
				this.viewport.Reset();
				this.scoreboard.Reset();
				this.background.Reset();
				this.isRunning = true;
			},
			this.volume
		);

		this.viewport = new Viewport(
			this.context,
			[this.background, this.scoreboard],
			[],
			[this.player, this.platform]
		);

		this.platform.viewport = this.viewport;

		let originalOnMove: (amountMoved: Point) => void = this.player.onMove;
		this.player.onMove = (amountMoved: Point) => {
			this.viewport.SlideUpTo(-this.player.yPosition + 50);
			this.background.SlideUpTo(-this.player.yPosition);

			if (this.player.yPosition > -(this.viewport.offset - this.canvas.height)) {
				this.isRunning = false;
				this.deathSound.play();
				this.menu.showMenu(this.scoreboard.totalPoints, this.player.fillColor);
			}

			if (originalOnMove) {
				originalOnMove(amountMoved);
			}
		};
	}

	public Start(): void {
		requestAnimationFrame((time: number) => { this.Tick(time); });
	}

	private Tick(timestamp: number): void {
		let deltaTime: number = this.lastTimestamp ? (timestamp - this.lastTimestamp) : 0;
		let scaledTime: number = deltaTime / Renderer.timescale;
		this.lastTimestamp = timestamp;
		this.lastFps = Math.round(1000 / deltaTime);

		this.Draw();

		if (this.isRunning === true) {
			this.player.Tick(scaledTime);
			this.platform.Tick(scaledTime);
			Collider.processCollisions([this.player, this.platform]);
		}

		this.controller.clearClick();

		requestAnimationFrame((time: number) => { this.Tick(time); });
	}

	private Draw(): void {
		if (this.isRunning) {
			this.viewport.Render(this.lastFps);
		} else {
			this.menu.Render(this.context);
		}

		this.volume.Render(this.context);
	}
}
