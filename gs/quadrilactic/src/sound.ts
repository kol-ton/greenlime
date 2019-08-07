export interface SoundOptions {
	volume?: number;
	isLooping?: boolean;
}

export class Sound {
	private static defaultVolume: number = 0.3;

	private sound: HTMLAudioElement;

	constructor(path: string, options: SoundOptions) {
		this.sound = new Audio(path);
		this.sound.volume = options.volume || Sound.defaultVolume;
		this.sound.loop = options.isLooping === true;
	}

	public play(): void {
		this.sound.play();
	}

	public set volume(newVolume: number) {
		this.sound.volume = newVolume;
	}
}
